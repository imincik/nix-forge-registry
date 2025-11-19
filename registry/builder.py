"""
Nix builder module for the container registry.

Handles building container images using Nix flakes.
"""

import logging
import os
import subprocess
from flask import abort

from .config import config
from .validation import validate_image_name, parse_image_name

logger = logging.getLogger(__name__)


def run_nix_build(flake_ref: str, description: str = "image") -> str:
    """
    Run nix build command and return output path.

    Args:
        flake_ref: Nix flake reference (e.g., "github:user/repo#package.image")
        description: Human-readable description for logging (e.g., "image", "containers")

    Returns:
        Absolute path to the Nix store output (file or directory)

    Raises:
        HTTPException: 500 if build fails
        HTTPException: 504 if build times out

    Behavior:
        - In DEBUG mode: streams build output line-by-line to logs
        - In normal mode: captures output silently
        - Respects NIX_BUILD_TIMEOUT configuration
    """
    logger.info(f"Building {description} with Nix: {flake_ref}")

    nix_build_cmd = [
        "nix",
        "build",
        flake_ref,
        "--print-out-paths",
    ]
    logger.debug(f"Running command: {' '.join(nix_build_cmd)}")

    # Stream output in debug mode, capture in normal mode
    is_debug = logger.getEffectiveLevel() == logging.DEBUG
    output_path = ""

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
                logger.error(f"Nix build failed with exit code {return_code}")
                abort(500, f"Failed to build {description}")

            # The last line should be the output path
            if not output_lines:
                logger.error(f"Nix build produced no output")
                abort(500, f"Failed to build {description}: no output")
            output_path = output_lines[-1].strip()
        else:
            # Normal mode: capture output without streaming
            nix_cmd = subprocess.run(
                nix_build_cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=config.NIX_BUILD_TIMEOUT,
            )
            output_path = nix_cmd.stdout.decode().strip()

    except subprocess.TimeoutExpired:
        logger.error(f"Nix build timed out after {config.NIX_BUILD_TIMEOUT}s")
        abort(504, f"Build timeout: {description} took too long to build")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode()
        logger.error(f"Nix build failed: {error_msg}")
        abort(500, f"Failed to build {description}")

    logger.debug(f"Nix build output path: {output_path}")

    # Verify output exists
    if not os.path.exists(output_path):
        logger.error(f"Expected build output not found: {output_path}")
        abort(404, f"Expected build output not found: {output_path}")

    logger.info(f"Build complete: {output_path}")
    return output_path


def build_image(image_name: str) -> str:
    """
    Build container image using Nix and return path to tarball.

    Supports two formats:
    1. packages/<package> - Builds {GITHUB_REPO}#{package}.image
    2. applications/<package>/<image> - Builds {GITHUB_REPO}#{package}.containers,
       then finds {image}.tar.gz tarball file in the output directory

    Args:
        image_name: Image name in format "packages/..." or "applications/..."

    Returns:
        Absolute path to the image tarball in Nix store

    Raises:
        HTTPException: 400 if image_name format is invalid
        HTTPException: 404 if build output or image not found
        HTTPException: 500 if Nix build fails
        HTTPException: 504 if build times out

    Directory Structure:
        Packages: {nix_output} is the tarball file directly
        Applications: {nix_output}/ contains multiple tarball files
            ├── web.tar.gz       (tarball file)
            ├── worker.tar.gz    (tarball file)
            └── api.tar.gz       (tarball file)

    Note:
        For applications, the image name is specified WITHOUT the .tar.gz extension
        in the URL, but the registry automatically appends it when looking for the file.

    Examples:
        >>> build_image("packages/python-web")
        '/nix/store/.../image.tar.gz'

        >>> build_image("applications/myapp/web")
        '/nix/store/.../web.tar.gz'
    """
    # Validate and parse image name
    validate_image_name(image_name)
    parsed = parse_image_name(image_name)

    if parsed["type"] == "package":
        # Build single image: nix build {repo}#{package}.image
        package = parsed["package"]
        flake_ref = f"{config.GITHUB_REPO}#{package}.image"
        tar_path = run_nix_build(flake_ref, f"package '{package}'")

        # Verify it's a file (tarball)
        if not os.path.isfile(tar_path):
            logger.error(f"Expected tarball file, got: {tar_path}")
            abort(500, f"Build output is not a file: {tar_path}")

        logger.info(f"Package '{package}' ready at {tar_path}")
        return tar_path

    elif parsed["type"] == "application":
        # Build multi-image: nix build {repo}#{package}.containers
        package = parsed["package"]
        image = parsed["image"]
        flake_ref = f"{config.GITHUB_REPO}#{package}.containers"
        containers_dir = run_nix_build(flake_ref, f"application '{package}'")

        # Verify it's a directory
        if not os.path.isdir(containers_dir):
            logger.error(f"Expected directory, got: {containers_dir}")
            abort(500, f"Build output is not a directory: {containers_dir}")

        # Look for {image}.tar.gz (add extension automatically)
        tar_path = os.path.join(containers_dir, f"{image}.tar.gz")
        if not os.path.exists(tar_path):
            logger.error(f"Image '{image}.tar.gz' not found in {containers_dir}")
            # List available images for debugging
            try:
                available = [f for f in os.listdir(containers_dir)
                           if os.path.isfile(os.path.join(containers_dir, f)) and f.endswith('.tar.gz')]
                # Strip .tar.gz for display
                available_names = [f[:-7] for f in available]
                logger.error(f"Available images: {available_names}")
            except Exception:
                pass
            abort(404, f"Image '{image}' not found in application '{package}'")

        # Verify it's a file
        if not os.path.isfile(tar_path):
            logger.error(f"Expected tarball file, got: {tar_path}")
            abort(500, f"Image path is not a file: {tar_path}")

        logger.info(f"Application '{package}' image '{image}' ready at {tar_path}")
        return tar_path

    else:
        # Should never reach here due to parse_image_name validation
        abort(500, "Internal error: unknown image type")
