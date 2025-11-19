# Nix Forge container registry

An OCI-compliant container registry that builds images on-demand using Nix.

Implements the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec) with backward compatibility for Docker Registry v2 clients.

## Configuration

Configure the registry using environment variables. See `.env.example` for all available options:

```bash
# Logging
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR

# Server
FLASK_HOST=0.0.0.0         # Bind address
FLASK_PORT=5000            # Bind port

# Nix Build
GITHUB_REPO=github:imincik/flake-forge  # Nix flake repository
NIX_BUILD_TIMEOUT=600      # Build timeout in seconds

# Cache
CACHE_SIZE=50              # Number of manifests to cache

# Validation
MAX_IMAGE_NAME_LENGTH=255  # Max characters in image name
MAX_TAG_LENGTH=128         # Max characters in tag
```

## Usage

### Run the Registry

```bash
# Default configuration
python registry.py

# With custom configuration
LOG_LEVEL=DEBUG FLASK_PORT=8080 python registry.py

# Debug mode streams nix build output in real-time
LOG_LEVEL=DEBUG python registry.py
```

### Pull Container with Podman

```bash
podman run -it --tls-verify=false --pull=always localhost:5000/<PACKAGE>:latest
```

### Run Container with K8s

```bash
kubectl run test-api --insecure-skip-tls-verify --image=<IP-ADDRESS>:5000/<PACKAGE>:latest --port=5000
```

## Features

- **OCI-compliant**: Implements OCI Distribution Specification v1.0
- **Docker compatible**: Supports Docker Registry v2 format via Accept headers
- **On-demand building**: Images are built using Nix when requested
- **Memory efficient**: Streams blobs without loading entire images into memory
- **Configurable**: All settings via environment variables
- **Input validation**: Prevents injection attacks
- **Real-time logging**: Debug mode streams nix build output line-by-line

## Manifest Formats

The registry supports both OCI and Docker manifest formats:

- **OCI format** (default): `application/vnd.oci.image.manifest.v1+json`
- **Docker format**: `application/vnd.docker.distribution.manifest.v2+json`

The format is automatically selected based on the client's `Accept` header.
