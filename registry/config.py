"""
Configuration module for the container registry.

Loads all configuration from environment variables with sensible defaults.
"""

import os


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
            FLASK_PORT: Server bind port. Default: 6443
            GITHUB_REPO: Nix flake repository URL. Default: github:imincik/nix-forge
            NIX_BUILD_TIMEOUT: Build timeout in seconds. Default: 600
            CACHE_SIZE: Number of manifests to cache. Default: 50
            MAX_IMAGE_NAME_LENGTH: Maximum image name length. Default: 255
            MAX_TAG_LENGTH: Maximum tag length. Default: 128
        """
        # Logging
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

        # Server
        self.FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
        self.FLASK_PORT = int(os.getenv("FLASK_PORT", "6443"))

        # Nix build
        self.GITHUB_REPO = os.getenv("GITHUB_REPO", "github:imincik/nix-forge")
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


# Global config instance
config = Config()
