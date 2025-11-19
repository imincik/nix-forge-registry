"""
Image metadata and blob handling module for the container registry.

Provides functions for loading image manifests and extracting blobs from tarballs.
"""

import json
import logging
import tarfile
from functools import lru_cache

from .config import config
from .validation import compute_sha256

logger = logging.getLogger(__name__)


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
