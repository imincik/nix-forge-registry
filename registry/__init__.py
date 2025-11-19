"""
OCI-compliant container registry with on-demand Nix builds.

This registry implements the OCI Distribution Specification v1.0 with backward
compatibility for Docker Registry v2 API. Images are built on-demand using Nix
when requested, eliminating the need for pre-built image storage.

Features:
    - OCI Distribution Specification compliant
    - Docker Registry v2 API compatible
    - On-demand image building with Nix
    - Support for single-image packages and multi-image applications
    - Memory-efficient blob streaming
    - LRU caching for manifest metadata
    - Comprehensive input validation
    - Configurable via environment variables
    - Real-time build output streaming in debug mode

Image Formats:
    1. Packages (single image):
       Format: packages/<package>
       Builds: nix build {repo}#{package}.image
       Example: packages/python-web

    2. Applications (multiple images):
       Format: applications/<package>/<image>
       Builds: nix build {repo}#{package}.containers
       Serves: {output}/{image}.tar.gz (extension added automatically)
       Example: applications/myapp/web (serves web.tar.gz)

See README.md for full documentation.
"""

__version__ = "0.1.0"
__author__ = "Ivan Mincik"

# Import key components for convenience
from .config import Config
from .validation import (
    compute_sha256,
    validate_image_name,
    validate_tag,
    validate_digest,
    parse_image_name,
)
from .builder import run_nix_build, build_image
from .image import load_image_manifest, get_blob_from_tar

__all__ = [
    "Config",
    "compute_sha256",
    "validate_image_name",
    "validate_tag",
    "validate_digest",
    "parse_image_name",
    "run_nix_build",
    "build_image",
    "load_image_manifest",
    "get_blob_from_tar",
]
