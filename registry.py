from flask import Flask, send_file, abort, Response, make_response
import tarfile
import json
import hashlib
import io
import os
import subprocess
import logging

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


def build_image(image_name: str) -> str:
    """
    Build image with Nix.
    """
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
