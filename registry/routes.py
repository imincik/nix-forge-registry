"""
Flask application and OCI registry endpoints.

Implements the OCI Distribution Specification v1.0 API endpoints.
"""

import io
import json
import logging
from flask import Flask, send_file, abort, Response, make_response, request

from .builder import build_image
from .image import load_image_manifest, get_blob_from_tar
from .validation import validate_image_name, validate_tag, validate_digest, compute_sha256

logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)


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


@app.route("/v2/<path:image_name>/manifests/<tag>", methods=["GET", "HEAD"])
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


@app.route("/v2/<path:image_name>/blobs/<digest>", methods=["GET", "HEAD"])
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
