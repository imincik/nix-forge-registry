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


# -------------------------------
# Configuration
# -------------------------------


class Config:
    """Registry configuration from environment variables."""

    def __init__(self):
        # Logging
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

        # Server
        self.FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
        self.FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))

        # Nix build
        self.GITHUB_REPO = os.getenv("GITHUB_REPO", "github:imincik/flake-forge")
        self.NIX_BUILD_TIMEOUT = int(os.getenv("NIX_BUILD_TIMEOUT", "600"))  # seconds

        # Cache
        self.CACHE_SIZE = int(os.getenv("CACHE_SIZE", "50"))

        # Validation limits
        self.MAX_IMAGE_NAME_LENGTH = int(os.getenv("MAX_IMAGE_NAME_LENGTH", "255"))
        self.MAX_TAG_LENGTH = int(os.getenv("MAX_TAG_LENGTH", "128"))

    def __repr__(self):
        """String representation for logging."""
        return (
            f"Config(LOG_LEVEL={self.LOG_LEVEL}, "
            f"FLASK_HOST={self.FLASK_HOST}, "
            f"FLASK_PORT={self.FLASK_PORT}, "
            f"GITHUB_REPO={self.GITHUB_REPO}, "
            f"CACHE_SIZE={self.CACHE_SIZE})"
        )


# Initialize configuration
config = Config()

# Configure logging
logging.basicConfig(
    level=config.LOG_LEVEL,
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
    if not name or len(name) > config.MAX_IMAGE_NAME_LENGTH:
        logger.warning(f"Invalid image name length: {len(name)}")
        abort(400, f"Invalid image name: must be 1-{config.MAX_IMAGE_NAME_LENGTH} characters")

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
    if not tag or len(tag) > config.MAX_TAG_LENGTH:
        logger.warning(f"Invalid tag length: {len(tag)}")
        abort(400, f"Invalid tag: must be 1-{config.MAX_TAG_LENGTH} characters")

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
        f"{config.GITHUB_REPO}#{image_name}.image",
        "--print-out-paths",
    ]
    logger.debug(f"Running command: {' '.join(nix_build_cmd)}")

    try:
        nix_cmd = subprocess.run(
            nix_build_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=config.NIX_BUILD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Nix build timed out for image '{image_name}' after {config.NIX_BUILD_TIMEOUT}s")
        abort(504, f"Build timeout: image '{image_name}' took too long to build")
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


@lru_cache(maxsize=config.CACHE_SIZE)
def load_image_manifest(tar_path: str) -> dict:
    """
    Load only the manifest and compute metadata WITHOUT loading full blobs into memory.

    Returns lightweight metadata with digests and sizes, but not the actual blob data.
    """
    logger.debug(f"Loading image manifest from {tar_path}")

    with tarfile.open(tar_path, "r:gz") as tar:
        manifest_member = tar.getmember("manifest.json")
        manifest_data = json.load(tar.extractfile(manifest_member))[0]

        config_name = manifest_data["Config"]
        layer_files = manifest_data["Layers"]
        logger.debug(f"Found config: {config_name}, layers: {len(layer_files)}")

        # Only read config to compute digest and size
        config_bytes = tar.extractfile(config_name).read()
        config_digest = compute_sha256(config_bytes)
        logger.debug(f"Config digest: {config_digest}, size: {len(config_bytes)} bytes")

        # Build lightweight layer metadata (NO bytes stored)
        layers = []
        total_size = len(config_bytes)
        for idx, layer_name in enumerate(layer_files, 1):
            layer_bytes = tar.extractfile(layer_name).read()
            digest = compute_sha256(layer_bytes)
            size = len(layer_bytes)
            total_size += size
            logger.debug(f"Layer {idx}/{len(layer_files)}: {digest}, size: {size} bytes")
            layers.append({
                "name": layer_name,
                "digest": digest,
                "size": size,
            })

        logger.info(f"Loaded manifest: {len(layers)} layers, total size: {total_size} bytes")

        return {
            "config": {
                "name": config_name,
                "digest": config_digest,
                "size": len(config_bytes),
                "bytes": config_bytes,  # Keep config in memory (small)
            },
            "layers": layers,
        }


def get_blob_from_tar(tar_path: str, digest: str) -> tuple[bytes | None, str | None]:
    """
    Stream a specific blob from tarfile by digest WITHOUT loading all layers.

    Returns (blob_bytes, mimetype) or (None, None) if not found.
    This avoids loading the entire image into memory.
    """
    logger.debug(f"Searching for blob {digest} in {tar_path}")

    with tarfile.open(tar_path, "r:gz") as tar:
        manifest_member = tar.getmember("manifest.json")
        manifest_data = json.load(tar.extractfile(manifest_member))[0]

        config_name = manifest_data["Config"]
        layer_files = manifest_data["Layers"]

        # Check config blob
        config_bytes = tar.extractfile(config_name).read()
        if compute_sha256(config_bytes) == digest:
            logger.debug(f"Found config blob: {digest}")
            return config_bytes, "application/vnd.docker.container.image.v1+json"

        # Check layer blobs (stream one at a time)
        for layer_name in layer_files:
            layer_bytes = tar.extractfile(layer_name).read()
            if compute_sha256(layer_bytes) == digest:
                logger.debug(f"Found layer blob: {digest}")
                return layer_bytes, "application/octet-stream"

    logger.debug(f"Blob not found: {digest}")
    return None, None


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
    meta = load_image_manifest(tar_path)

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

    # Stream blob directly from tar without loading all layers
    blob_bytes, mimetype = get_blob_from_tar(tar_path, digest)

    if blob_bytes is None:
        logger.warning(f"Blob not found: image='{image_name}', digest='{digest}'")
        abort(404)

    logger.debug(f"Serving blob: {digest}, size: {len(blob_bytes)} bytes")
    resp = send_file(
        io.BytesIO(blob_bytes),
        mimetype=mimetype,
    )
    resp.headers["Docker-Content-Digest"] = digest
    logger.info(f"Blob sent: image='{image_name}', digest='{digest}'")
    return resp


# -------------------------------
# Main
# -------------------------------

if __name__ == "__main__":
    debug_mode = logger.getEffectiveLevel() == logging.DEBUG
    logger.info(f"Starting container registry service on {config.FLASK_HOST}:{config.FLASK_PORT}")
    logger.info(f"Configuration: {config}")
    logger.info(f"Log level: {logging.getLevelName(logger.getEffectiveLevel())}")
    if debug_mode:
        logger.info("Flask debug mode enabled")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=debug_mode)
