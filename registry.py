"""
OCI-compliant container registry with on-demand Nix builds.

This registry implements the OCI Distribution Specification v1.0 with backward
compatibility for Docker Registry v2 API. Images are built on-demand using Nix
when requested, eliminating the need for pre-built image storage.

Features:
    - OCI Distribution Specification compliant
    - Docker Registry v2 API compatible
    - On-demand image building with Nix
    - Memory-efficient blob streaming
    - LRU caching for manifest metadata
    - Comprehensive input validation
    - Configurable via environment variables
    - Real-time build output streaming in debug mode

Architecture:
    1. Client requests manifest (GET /v2/<name>/manifests/<tag>)
    2. Registry builds image using Nix if not cached
    3. Registry extracts and caches manifest metadata
    4. Registry returns manifest in OCI or Docker format
    5. Client requests blobs (GET /v2/<name>/blobs/<digest>)
    6. Registry streams requested blobs from tarball

OCI Endpoints:
    - GET /v2/ - Version check
    - GET/HEAD /v2/<name>/manifests/<tag> - Get/check manifest
    - GET/HEAD /v2/<name>/blobs/<digest> - Get/check blob

Environment Variables:
    LOG_LEVEL, FLASK_HOST, FLASK_PORT, GITHUB_REPO, NIX_BUILD_TIMEOUT,
    CACHE_SIZE, MAX_IMAGE_NAME_LENGTH, MAX_TAG_LENGTH

Example:
    $ LOG_LEVEL=DEBUG python registry.py
    $ podman pull localhost:5000/myimage:latest

See README.md for full documentation.
"""

from flask import Flask, send_file, abort, Response, make_response, request
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
    """
    Registry configuration from environment variables.

    Loads all configuration values from environment variables with sensible defaults.
    All settings can be overridden by setting the corresponding environment variable.
    """

    def __init__(self):
        """
        Initialize configuration from environment variables.

        Environment Variables:
            LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR). Default: INFO
            FLASK_HOST: Server bind address. Default: 0.0.0.0
            FLASK_PORT: Server bind port. Default: 5000
            GITHUB_REPO: Nix flake repository URL. Default: github:imincik/flake-forge
            NIX_BUILD_TIMEOUT: Build timeout in seconds. Default: 600
            CACHE_SIZE: Number of manifests to cache. Default: 50
            MAX_IMAGE_NAME_LENGTH: Maximum image name length. Default: 255
            MAX_TAG_LENGTH: Maximum tag length. Default: 128
        """
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
    """
    Compute SHA256 digest in OCI/Docker format.

    Args:
        data: Bytes to hash

    Returns:
        String in format "sha256:<64 hex chars>"

    Example:
        >>> compute_sha256(b"hello")
        'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    h = hashlib.sha256()
    h.update(data)
    return "sha256:" + h.hexdigest()


def validate_image_name(name: str) -> None:
    """
    Validate image name to prevent injection attacks.

    Args:
        name: Image name to validate

    Raises:
        HTTPException: 400 Bad Request if name is invalid

    Validation Rules:
        - Must be 1-{MAX_IMAGE_NAME_LENGTH} characters (configurable)
        - Only alphanumeric characters, dots (.), hyphens (-), and underscores (_)
        - No special characters or path separators allowed

    Security:
        Prevents command injection when used in subprocess calls to Nix.
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
    Validate container image tag.

    Args:
        tag: Tag name to validate

    Raises:
        HTTPException: 400 Bad Request if tag is invalid

    Validation Rules:
        - Must be 1-{MAX_TAG_LENGTH} characters (configurable)
        - Only alphanumeric characters, dots (.), hyphens (-), and underscores (_)
        - Common tags: latest, v1.0.0, prod, staging, etc.
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
    Validate SHA256 digest format per OCI specification.

    Args:
        digest: Digest string to validate

    Raises:
        HTTPException: 400 Bad Request if digest is invalid

    Format:
        Must match: sha256:<64 lowercase hex characters>

    Example:
        Valid: "sha256:abc123...def" (64 hex chars after colon)
        Invalid: "sha256:ABC123" (uppercase), "md5:123" (wrong algorithm)
    """
    if not re.match(r'^sha256:[a-f0-9]{64}$', digest):
        logger.warning(f"Invalid digest format: {digest}")
        abort(400, "Invalid digest: must be sha256:<64 hex characters>")

    logger.debug(f"Digest validated: {digest}")


def build_image(image_name: str) -> str:
    """
    Build container image using Nix and return path to tarball.

    Args:
        image_name: Name of the image to build (validated before use)

    Returns:
        Absolute path to the built image tarball in Nix store

    Raises:
        HTTPException: 400 if image_name is invalid
        HTTPException: 404 if build output not found
        HTTPException: 500 if Nix build fails
        HTTPException: 504 if build times out

    Behavior:
        - In DEBUG mode: streams build output line-by-line to logs
        - In normal mode: captures output silently
        - Respects NIX_BUILD_TIMEOUT configuration
        - Validates image_name to prevent command injection

    Note:
        Builds from flake: {GITHUB_REPO}#{image_name}.image
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

    # Stream output in debug mode, capture in normal mode
    is_debug = logger.getEffectiveLevel() == logging.DEBUG
    tar_path = ""

    try:
        if is_debug:
            # Stream output line-by-line in debug mode
            process = subprocess.Popen(
                nix_build_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                bufsize=1,  # Line buffered
            )

            output_lines = []
            for line in process.stdout:
                line = line.rstrip()
                if line:  # Only log non-empty lines
                    logger.debug(f"[nix] {line}")
                    output_lines.append(line)

            return_code = process.wait(timeout=config.NIX_BUILD_TIMEOUT)

            if return_code != 0:
                logger.error(f"Nix build failed for image '{image_name}' with exit code {return_code}")
                abort(500, f"Failed to build image '{image_name}'")

            # The last line should be the output path
            if not output_lines:
                logger.error(f"Nix build produced no output for image '{image_name}'")
                abort(500, f"Failed to build image '{image_name}': no output")
            tar_path = output_lines[-1].strip()
        else:
            # Normal mode: capture output without streaming
            nix_cmd = subprocess.run(
                nix_build_cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=config.NIX_BUILD_TIMEOUT,
            )
            tar_path = nix_cmd.stdout.decode().strip()

    except subprocess.TimeoutExpired:
        logger.error(f"Nix build timed out for image '{image_name}' after {config.NIX_BUILD_TIMEOUT}s")
        abort(504, f"Build timeout: image '{image_name}' took too long to build")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode()
        logger.error(f"Nix build failed for image '{image_name}': {error_msg}")
        abort(500, f"Failed to build image '{image_name}'")

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
    Load image manifest and compute metadata without loading full blobs into memory.

    This function is memory-efficient: it computes digests and sizes but doesn't
    store layer blob data in the cache. Only the small config blob is kept.

    Args:
        tar_path: Path to Docker/OCI image tarball (from nix build)

    Returns:
        Dictionary with structure:
        {
            "config": {
                "name": str,         # Config filename
                "digest": str,       # sha256:...
                "size": int,         # Size in bytes
                "bytes": bytes       # Actual config data (small, ~10KB)
            },
            "layers": [
                {
                    "name": str,     # Layer filename
                    "digest": str,   # sha256:...
                    "size": int      # Size in bytes
                    # NOTE: No "bytes" field - saves memory!
                },
                ...
            ]
        }

    Caching:
        Results are cached with LRU cache (size configurable via CACHE_SIZE).
        Only metadata is cached, not the actual layer data.

    Performance:
        For a 500MB image with 10 layers, this caches ~1KB instead of 500MB.
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
    Stream a specific blob from tarfile by digest without loading all layers.

    This function searches for a specific blob (config or layer) by its digest
    and returns only that blob, avoiding the need to load the entire image.

    Args:
        tar_path: Path to Docker/OCI image tarball
        digest: SHA256 digest in format "sha256:<64 hex chars>"

    Returns:
        Tuple of (blob_bytes, mimetype) if found, or (None, None) if not found.

        Mimetypes:
        - Config: "application/vnd.oci.image.config.v1+json"
        - Layers: "application/vnd.oci.image.layer.v1.tar+gzip"

    Performance:
        Streams blobs one at a time. For an image with 10 layers where the
        requested blob is layer 3, only layers 1-3 are loaded into memory.

    Example:
        >>> blob, mime = get_blob_from_tar("/nix/store/...", "sha256:abc...")
        >>> if blob:
        ...     print(f"Found {len(blob)} bytes of type {mime}")
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
            # Use OCI media type for config
            return config_bytes, "application/vnd.oci.image.config.v1+json"

        # Check layer blobs (stream one at a time)
        for layer_name in layer_files:
            layer_bytes = tar.extractfile(layer_name).read()
            if compute_sha256(layer_bytes) == digest:
                logger.debug(f"Found layer blob: {digest}")
                # Use OCI media type for layers
                return layer_bytes, "application/vnd.oci.image.layer.v1.tar+gzip"

    logger.debug(f"Blob not found: {digest}")
    return None, None


# -------------------------------
# Registry Endpoints
# -------------------------------


@app.route("/v2/")
def v2_root():
    """
    OCI Distribution API version check endpoint.

    Returns HTTP 200 to indicate the registry supports the OCI Distribution
    Specification / Docker Registry v2 API.

    Required by OCI spec: clients check this endpoint before attempting
    to pull images.

    Returns:
        Response with status 200 and Docker-Distribution-API-Version header

    Headers:
        Docker-Distribution-API-Version: registry/2.0
    """
    logger.info("Registry v2 API root accessed")
    resp = Response(status=200)
    resp.headers["Docker-Distribution-API-Version"] = "registry/2.0"
    return resp


@app.route("/v2/<image_name>/manifests/<tag>", methods=["GET", "HEAD"])
def get_manifest(image_name, tag):
    """
    Get or check container image manifest (OCI Distribution Spec).

    Builds the image with Nix (if needed) and returns the manifest in either
    OCI or Docker format based on the client's Accept header.

    Args:
        image_name: Name of the image (validated)
        tag: Image tag (validated)

    Methods:
        GET: Returns full manifest JSON
        HEAD: Returns only headers (Content-Length, digest, etc.)

    Request Headers:
        Accept: Optional. Determines manifest format.
            - Contains "application/vnd.docker.distribution.manifest": Docker format
            - Otherwise: OCI format (default)

    Response Headers:
        Content-Type: application/vnd.oci.image.manifest.v1+json (or Docker variant)
        Content-Length: Size of manifest in bytes
        Docker-Content-Digest: SHA256 digest of manifest

    Returns:
        - GET: JSON manifest with config and layer references
        - HEAD: Empty body with headers only

    Response Format (OCI):
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:...",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:...",
                    "size": 5678
                }
            ]
        }

    Raises:
        400: Invalid image_name or tag
        404: Build output not found
        500: Build failed
        504: Build timeout
    """
    validate_image_name(image_name)
    validate_tag(tag)

    logger.info(f"Manifest requested: image='{image_name}', tag='{tag}', method={request.method}")

    # Check Accept header to determine manifest format
    accept_header = request.headers.get("Accept", "")
    use_docker_format = "application/vnd.docker.distribution.manifest" in accept_header

    logger.debug(f"Accept header: {accept_header}, using Docker format: {use_docker_format}")

    tar_path = build_image(image_name)
    meta = load_image_manifest(tar_path)

    # Build manifest in OCI format (or Docker format for compatibility)
    if use_docker_format:
        # Docker Registry v2 format
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
        content_type = "application/vnd.docker.distribution.manifest.v2+json"
    else:
        # OCI format (default)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": meta["config"]["digest"],
                "size": meta["config"]["size"],
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer["digest"],
                    "size": layer["size"],
                }
                for layer in meta["layers"]
            ],
        }
        content_type = "application/vnd.oci.image.manifest.v1+json"

    manifest_bytes = json.dumps(manifest).encode("utf-8")
    manifest_digest = compute_sha256(manifest_bytes)
    logger.debug(
        f"Manifest digest: {manifest_digest}, size: {len(manifest_bytes)} bytes, format: {content_type}"
    )

    # For HEAD requests, return empty body with headers
    if request.method == "HEAD":
        resp = Response(status=200)
        resp.headers["Content-Type"] = content_type
        resp.headers["Content-Length"] = len(manifest_bytes)
        resp.headers["Docker-Content-Digest"] = manifest_digest
        logger.info(f"Manifest HEAD: image='{image_name}', tag='{tag}', digest={manifest_digest}, format={content_type}")
        return resp

    # For GET requests, return full manifest
    resp = make_response(manifest_bytes)
    resp.headers["Content-Type"] = content_type
    resp.headers["Content-Length"] = len(manifest_bytes)
    resp.headers["Docker-Content-Digest"] = manifest_digest

    logger.info(
        f"Manifest sent: image='{image_name}', tag='{tag}', digest={manifest_digest}, format={content_type}"
    )
    return resp


@app.route("/v2/<image_name>/blobs/<digest>", methods=["GET", "HEAD"])
def get_blob(image_name, digest):
    """
    Get or check a blob (config or layer) by digest (OCI Distribution Spec).

    Retrieves a specific blob from the image tarball without loading all
    layers into memory. Supports both config blobs and layer blobs.

    Args:
        image_name: Name of the image (validated)
        digest: SHA256 digest in format "sha256:<64 hex chars>" (validated)

    Methods:
        GET: Returns full blob content
        HEAD: Returns only headers (Content-Length, digest, Content-Type)

    Response Headers:
        Content-Type:
            - Config: application/vnd.oci.image.config.v1+json
            - Layers: application/vnd.oci.image.layer.v1.tar+gzip
        Content-Length: Size of blob in bytes
        Docker-Content-Digest: SHA256 digest (echoed from request)

    Returns:
        - GET: Binary blob content (config JSON or layer tarball)
        - HEAD: Empty body with headers only

    Performance:
        Memory-efficient: streams only the requested blob, not the entire image.

    Raises:
        400: Invalid image_name or digest format
        404: Blob not found or build output not found
        500: Build failed
        504: Build timeout

    Example Flow:
        1. Client requests: GET /v2/myapp/blobs/sha256:abc123...
        2. Registry builds image with Nix (or uses cache)
        3. Registry searches tarball for matching digest
        4. Registry returns matching blob (config or layer)
    """
    validate_image_name(image_name)
    validate_digest(digest)

    logger.info(f"Blob requested: image='{image_name}', digest='{digest}', method={request.method}")

    tar_path = build_image(image_name)

    # Stream blob directly from tar without loading all layers
    blob_bytes, mimetype = get_blob_from_tar(tar_path, digest)

    if blob_bytes is None:
        logger.warning(f"Blob not found: image='{image_name}', digest='{digest}'")
        abort(404)

    blob_size = len(blob_bytes)
    logger.debug(f"Serving blob: {digest}, size: {blob_size} bytes")

    # For HEAD requests, return headers only
    if request.method == "HEAD":
        resp = Response(status=200)
        resp.headers["Content-Type"] = mimetype
        resp.headers["Content-Length"] = blob_size
        resp.headers["Docker-Content-Digest"] = digest
        logger.info(f"Blob HEAD: image='{image_name}', digest='{digest}'")
        return resp

    # For GET requests, return full blob
    resp = send_file(
        io.BytesIO(blob_bytes),
        mimetype=mimetype,
    )
    resp.headers["Content-Length"] = blob_size
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
