"""
Input validation module for the container registry.

Provides validation functions for image names, tags, digests, and parsing.
"""

import hashlib
import logging
import re
from flask import abort

from .config import config

logger = logging.getLogger(__name__)


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
        name: Image name to validate (e.g., "packages/python-web" or "applications/myapp/web")

    Raises:
        HTTPException: 400 Bad Request if name is invalid

    Validation Rules:
        - Must be 1-{MAX_IMAGE_NAME_LENGTH} characters (configurable)
        - Only alphanumeric characters, dots (.), hyphens (-), underscores (_), and slashes (/)
        - Must start with "packages/" or "applications/" (enforced by parse_image_name)
        - No special characters that could enable command injection

    Note:
        This validates character set only. Format validation (prefix requirement)
        is done by parse_image_name().

    Security:
        Prevents command injection when used in subprocess calls to Nix.

    Examples:
        >>> validate_image_name("packages/python-web")  # OK
        >>> validate_image_name("applications/app/web")  # OK
        >>> validate_image_name("pkg;rm -rf")  # Raises 400 (semicolon)
    """
    if not name or len(name) > config.MAX_IMAGE_NAME_LENGTH:
        logger.warning(f"Invalid image name length: {len(name)}")
        abort(400, f"Invalid image name: must be 1-{config.MAX_IMAGE_NAME_LENGTH} characters")

    if not re.match(r'^[a-zA-Z0-9._/-]+$', name):
        logger.warning(f"Invalid image name format: {name}")
        abort(400, "Invalid image name: only alphanumeric, dots, hyphens, underscores, and slashes allowed")

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


def parse_image_name(image_name: str) -> dict:
    """
    Parse image name to determine type and extract components.

    Supports two formats:
    1. packages/<package> - Single image from .image output
    2. applications/<package>/<image> - Multi-image from .containers output
       (image name specified without .tar.gz extension)

    Args:
        image_name: Image name in format "packages/..." or "applications/..."

    Returns:
        Dictionary with structure:
        - For packages: {"type": "package", "package": "<package>", "image": None}
        - For applications: {"type": "application", "package": "<package>", "image": "<image>"}

    Raises:
        HTTPException: 400 if format is invalid or missing required prefix

    Note:
        For applications, the image name is specified WITHOUT .tar.gz extension.
        The build_image() function will automatically append .tar.gz when looking
        for the file in the containers directory.

    Examples:
        >>> parse_image_name("packages/python-web")
        {'type': 'package', 'package': 'python-web', 'image': None}

        >>> parse_image_name("applications/myapp/web")
        {'type': 'application', 'package': 'myapp', 'image': 'web'}
        # Will serve: /nix/store/.../web.tar.gz
    """
    # Check for packages/ prefix
    if image_name.startswith("packages/"):
        package = image_name[len("packages/"):]
        if not package:
            logger.warning(f"Empty package name in: {image_name}")
            abort(400, "Invalid format: packages/<package> required. Example: packages/python-web")
        if "/" in package:
            logger.warning(f"Invalid package name with slash: {image_name}")
            abort(400, "Invalid format: packages/<package> should not contain additional slashes. Example: packages/python-web")
        return {"type": "package", "package": package, "image": None}

    # Check for applications/ prefix
    if image_name.startswith("applications/"):
        remainder = image_name[len("applications/"):]
        parts = remainder.split("/")
        if len(parts) != 2:
            logger.warning(f"Invalid applications format: {image_name}")
            abort(400, "Invalid format: applications/<package>/<image> required. Example: applications/myapp/web")
        package, image = parts
        if not package or not image:
            logger.warning(f"Empty component in: {image_name}")
            abort(400, "Invalid format: both package and image must be non-empty. Example: applications/myapp/web")
        return {"type": "application", "package": package, "image": image}

    # No valid prefix found
    logger.warning(f"Image name missing required prefix: {image_name}")
    abort(400,
          "Invalid format: image name must start with 'packages/' or 'applications/'. "
          "Valid formats:\n"
          "  - packages/<package>              (example: packages/python-web)\n"
          "  - applications/<package>/<image>  (example: applications/myapp/web)")
