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

Architecture:
    1. Client requests manifest (GET /v2/<name>/manifests/<tag>)
    2. Registry parses image name to determine type
    3. Registry builds package or application using Nix
    4. For applications, locates specific image in output directory
    5. Registry extracts and caches manifest metadata
    6. Registry returns manifest in OCI or Docker format
    7. Client requests blobs (GET /v2/<name>/blobs/<digest>)
    8. Registry streams requested blobs from tarball

OCI Endpoints:
    - GET /v2/ - Version check
    - GET/HEAD /v2/<name>/manifests/<tag> - Get/check manifest
    - GET/HEAD /v2/<name>/blobs/<digest> - Get/check blob

Environment Variables:
    LOG_LEVEL, FLASK_HOST, FLASK_PORT, GITHUB_REPO, NIX_BUILD_TIMEOUT,
    CACHE_SIZE, MAX_IMAGE_NAME_LENGTH, MAX_TAG_LENGTH

Example:
    $ LOG_LEVEL=DEBUG python app.py
    $ podman pull localhost:6443/packages/python-web:latest
    $ podman pull localhost:6443/applications/myapp/web:latest

See README.md for full documentation.
"""

import logging

from registry.config import config
from registry.routes import app

# Configure logging
logging.basicConfig(
    level=config.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point for the registry application."""
    debug_mode = logger.getEffectiveLevel() == logging.DEBUG
    logger.info(f"Starting container registry service on {config.FLASK_HOST}:{config.FLASK_PORT}")
    logger.info(f"Configuration: {config}")
    logger.info(f"Log level: {logging.getLevelName(logger.getEffectiveLevel())}")
    if debug_mode:
        logger.info("Flask debug mode enabled")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=debug_mode)


if __name__ == "__main__":
    main()
