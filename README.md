# Nix Forge container registry

A Docker-compatible container registry that builds images on-demand using Nix.

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
```

### Pull Container with Podman

```bash
podman run -it --tls-verify=false --pull=always localhost:5000/<PACKAGE>:latest
```

### Run Container with K8s

```bash
kubectl run test-api --insecure-skip-tls-verify --image=<IP-ADDRESS>:5000/<PACKAGE>:latest --port=5000
```
