from flask import Flask, send_file, abort, Response, make_response
import tarfile
import json
import hashlib
import io
import os
import subprocess

app = Flask(__name__)


# -------------------------------
# Utility Functions
# -------------------------------

def compute_sha256(data: bytes) -> str:
    """Return Docker-style sha256 digest."""
    h = hashlib.sha256()
    h.update(data)
    return "sha256:" + h.hexdigest()


def build_image_if_missing(image_name: str) -> str:
    """
    Ensure ./result/<image_name>.tar.gz exists.
    If not, run `nix build .#<image_name>.image`.
    """
    # FIXME:
    # check    nix eval github:imincik/flake-forge#geos.image.outPath

    # tar_path = os.path.join(RESULT_DIR, f"{image_name}.tar.gz")
    # tar_path = os.path.join(RESULT_DIR)

    # If it already exists, use it
    # if os.path.exists(tar_path):
        # return tar_path

    # Otherwise, build it with nix
    print(f"[INFO] Image '{image_name}' not found. Building with nix ...")
    try:
        nix_cmd = subprocess.run(
            # FIXME: --builders
            ["nix", "build", f"github:imincik/flake-forge#{image_name}.image", "--print-out-paths",  "--builders", "\"\""],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print("[ERROR] nix build failed:", e.stderr.decode())
        abort(500, f"Failed to build image '{image_name}'")

    tar_path=nix_cmd.stdout.decode().strip()

    # After build, look for resulting tarball
    if not os.path.exists(tar_path):
        abort(404, f"Expected build output not found: {tar_path}")

    print(f"[INFO] Image '{image_name}' ready at {tar_path}")
    return tar_path


def load_image_metadata(tar_path: str):
    """Extract manifest.json, config, and layers from a Docker save tar.gz."""
    with tarfile.open(tar_path, "r:gz") as tar:
        manifest_member = tar.getmember("manifest.json")
        manifest_data = json.load(tar.extractfile(manifest_member))[0]

        config_name = manifest_data["Config"]
        layer_files = manifest_data["Layers"]

        config_bytes = tar.extractfile(config_name).read()
        config_digest = compute_sha256(config_bytes)

        layers = []
        for layer_name in layer_files:
            layer_bytes = tar.extractfile(layer_name).read()
            digest = compute_sha256(layer_bytes)
            layers.append({
                "name": layer_name,
                "digest": digest,
                "size": len(layer_bytes),
                "bytes": layer_bytes,
            })

        return {
            "config": {
                "name": config_name,
                "digest": config_digest,
                "size": len(config_bytes),
                "bytes": config_bytes,
            },
            "layers": layers,
        }


# -------------------------------
# Registry Endpoints
# -------------------------------

@app.route("/v2/")
def v2_root():
    """Docker registry v2 API root endpoint."""
    return Response(status=200)


@app.route("/v2/<image_name>/manifests/<tag>")
def get_manifest(image_name, tag):
    tar_path = build_image_if_missing(image_name)
    meta = load_image_metadata(tar_path)

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

    manifest_bytes = json.dumps(manifest).encode("utf-8")
    manifest_digest = compute_sha256(manifest_bytes)

    resp = make_response(manifest_bytes)
    resp.headers["Content-Type"] = "application/vnd.docker.distribution.manifest.v2+json"
    resp.headers["Docker-Content-Digest"] = manifest_digest
    return resp


@app.route("/v2/<image_name>/blobs/<digest>")
def get_blob(image_name, digest):
    tar_path = build_image_if_missing(image_name)
    meta = load_image_metadata(tar_path)

    # Config blob
    if digest == meta["config"]["digest"]:
        resp = send_file(
            io.BytesIO(meta["config"]["bytes"]),
            mimetype="application/vnd.docker.container.image.v1+json",
        )
        resp.headers["Docker-Content-Digest"] = digest
        return resp

    # Layer blobs
    for layer in meta["layers"]:
        if digest == layer["digest"]:
            resp = send_file(
                io.BytesIO(layer["bytes"]),
                mimetype="application/octet-stream",
            )
            resp.headers["Docker-Content-Digest"] = digest
            return resp

    abort(404)


# -------------------------------
# Main
# -------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

