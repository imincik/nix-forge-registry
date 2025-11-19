from flask import Flask, send_file, abort, Response, make_response
import tarfile
import json
import hashlib
import io
import os
import subprocess
import logging
import re

from functools import lru_cache


# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


# -------------------------------
# Utility Functions
# -------------------------------


def compute_sha256(data: bytes) -> str:
    """Return Docker-style sha256 digest."""
    h = hashlib.sha256()
    h.update(data)
    return "sha256:" + h.hexdigest()


def validate_image_name(name: str) -> None:
    """
    Validate image name to prevent injection attacks.

    Allows only alphanumeric characters, hyphens, underscores, and dots.
    Raises 400 error if invalid.
    """
    if not name or len(name) > 255:
        logger.warning(f"Invalid image name length: {len(name)}")
        abort(400, "Invalid image name: must be 1-255 characters")

    if not re.match(r'^[a-zA-Z0-9._-]+$', name):
        logger.warning(f"Invalid image name format: {name}")
        abort(400, "Invalid image name: only alphanumeric, dots, hyphens, and underscores allowed")

    logger.debug(f"Image name validated: {name}")


def validate_tag(tag: str) -> None:
    """
    Validate tag name.

    Allows alphanumeric characters, hyphens, underscores, and dots.
    Raises 400 error if invalid.
    """
    if not tag or len(tag) > 128:
        logger.warning(f"Invalid tag length: {len(tag)}")
        abort(400, "Invalid tag: must be 1-128 characters")

    if not re.match(r'^[a-zA-Z0-9._-]+$', tag):
        logger.warning(f"Invalid tag format: {tag}")
        abort(400, "Invalid tag: only alphanumeric, dots, hyphens, and underscores allowed")

    logger.debug(f"Tag validated: {tag}")


def validate_digest(digest: str) -> None:
    """
    Validate SHA256 digest format.

    Must match format: sha256:<64 hex chars>
    Raises 400 error if invalid.
    """
    if not re.match(r'^sha256:[a-f0-9]{64}$', digest):
        logger.warning(f"Invalid digest format: {digest}")
        abort(400, "Invalid digest: must be sha256:<64 hex characters>")

    logger.debug(f"Digest validated: {digest}")


def build_image(image_name: str) -> str:
    """
    Build image with Nix.
    """
    # Extra validation layer before using in subprocess
    validate_image_name(image_name)

    logger.info(f"Building image '{image_name}' with Nix ...")

    nix_build_cmd = [
        "nix",
        "build",
        f"github:imincik/flake-forge#{image_name}.image",
        "--print-out-paths",
    ]
    logger.debug(f"Running command: {' '.join(nix_build_cmd)}")

    try:
        nix_cmd = subprocess.run(
            nix_build_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode()
        logger.error(f"Nix build failed for image '{image_name}': {error_msg}")
        abort(500, f"Failed to build image '{image_name}'")

    tar_path = nix_cmd.stdout.decode().strip()
    logger.debug(f"Nix build output path: {tar_path}")

    # After build, look for resulting tarball
    if not os.path.exists(tar_path):
        logger.error(f"Expected build output not found: {tar_path}")
        abort(404, f"Expected build output not found: {tar_path}")

    logger.info(f"Image '{image_name}' ready at {tar_path}")
    return tar_path


@lru_cache(maxsize=50)
def load_image_metadata(tar_path: str):
    """Extract manifest.json, config, and layers from a tar.gz."""
    logger.debug(f"Loading image metadata from {tar_path}")

    with tarfile.open(tar_path, "r:gz") as tar:
        manifest_member = tar.getmember("manifest.json")
        manifest_data = json.load(tar.extractfile(manifest_member))[0]

        config_name = manifest_data["Config"]
        layer_files = manifest_data["Layers"]
        logger.debug(f"Found config: {config_name}, layers: {len(layer_files)}")

        config_bytes = tar.extractfile(config_name).read()
        config_digest = compute_sha256(config_bytes)
        logger.debug(f"Config digest: {config_digest}, size: {len(config_bytes)} bytes")

        layers = []
        for idx, layer_name in enumerate(layer_files, 1):
            layer_bytes = tar.extractfile(layer_name).read()
            digest = compute_sha256(layer_bytes)
            logger.debug(
                f"Layer {idx}/{len(layer_files)}: {digest}, size: {len(layer_bytes)} bytes"
            )
            layers.append(
                {
                    "name": layer_name,
                    "digest": digest,
                    "size": len(layer_bytes),
                    "bytes": layer_bytes,
                }
            )

        logger.info(
            f"Loaded metadata: {len(layers)} layers, total size: {sum(l['size'] for l in layers) + len(config_bytes)} bytes"
        )

        return {
            "config": {
                "name": config_name,
                "digest": config_digest,
                "size": len(config_bytes),
                "bytes": config_bytes,
            },
            "layers": layers,
        }


# -------------------------------
# Registry Endpoints
# -------------------------------


@app.route("/v2/")
def v2_root():
    """Container image registry v2 API root endpoint."""
    logger.info("Registry v2 API root accessed")
    return Response(status=200)


@app.route("/v2/<image_name>/manifests/<tag>")
def get_manifest(image_name, tag):
    validate_image_name(image_name)
    validate_tag(tag)

    logger.info(f"Manifest requested: image='{image_name}', tag='{tag}'")

    tar_path = build_image(image_name)
    meta = load_image_metadata(tar_path)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": meta["config"]["digest"],
            "size": meta["config"]["size"],
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": layer["digest"],
                "size": layer["size"],
            }
            for layer in meta["layers"]
        ],
    }

    manifest_bytes = json.dumps(manifest).encode("utf-8")
    manifest_digest = compute_sha256(manifest_bytes)
    logger.debug(
        f"Manifest digest: {manifest_digest}, size: {len(manifest_bytes)} bytes"
    )

    resp = make_response(manifest_bytes)
    resp.headers["Content-Type"] = (
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    resp.headers["Docker-Content-Digest"] = manifest_digest

    logger.info(
        f"Manifest sent: image='{image_name}', tag='{tag}', digest={manifest_digest}"
    )
    return resp


@app.route("/v2/<image_name>/blobs/<digest>")
def get_blob(image_name, digest):
    validate_image_name(image_name)
    validate_digest(digest)

    logger.info(f"Blob requested: image='{image_name}', digest='{digest}'")

    tar_path = build_image(image_name)
    meta = load_image_metadata(tar_path)

    # Config blob
    if digest == meta["config"]["digest"]:
        logger.debug(
            f"Serving config blob: {digest}, size: {meta['config']['size']} bytes"
        )
        resp = send_file(
            io.BytesIO(meta["config"]["bytes"]),
            mimetype="application/vnd.docker.container.image.v1+json",
        )
        resp.headers["Docker-Content-Digest"] = digest
        logger.info(f"Config blob sent: image='{image_name}', digest='{digest}'")
        return resp

    # Layer blobs
    for layer in meta["layers"]:
        if digest == layer["digest"]:
            logger.debug(f"Serving layer blob: {digest}, size: {layer['size']} bytes")
            resp = send_file(
                io.BytesIO(layer["bytes"]),
                mimetype="application/octet-stream",
            )
            resp.headers["Docker-Content-Digest"] = digest
            logger.info(f"Layer blob sent: image='{image_name}', digest='{digest}'")
            return resp

    logger.warning(f"Blob not found: image='{image_name}', digest='{digest}'")
    abort(404)


# -------------------------------
# Main
# -------------------------------

if __name__ == "__main__":
    debug_mode = logger.getEffectiveLevel() == logging.DEBUG
    logger.info("Starting container registry service on 0.0.0.0:5000")
    logger.info(f"Log level: {logging.getLevelName(logger.getEffectiveLevel())}")
    if debug_mode:
        logger.info("Flask debug mode enabled")
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
