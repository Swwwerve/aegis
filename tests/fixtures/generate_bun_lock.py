"""Build a trusted public fixture; extract its legacy lock offline without mounts."""

import base64
import io
from pathlib import Path

import docker

DOCKERFILE = b"""FROM oven/bun:1.1.38@sha256:5148f6742ac31fac28e6eab391ab1f11f6dfc0c8512c7a3679b374ec470f5982
WORKDIR /fixture
RUN echo '{"name":"fixture","dependencies":{"is-odd":"3.0.1"}}' > package.json && bun install --ignore-scripts
"""

if __name__ == "__main__":
    client = docker.from_env()
    image, _ = client.images.build(
        fileobj=io.BytesIO(DOCKERFILE), tag="aegis-bun-lock-fixture:legacy", rm=True
    )
    container = client.containers.create(
        image.id,
        entrypoint=["tail"],
        command=["-f", "/dev/null"],
        network_mode="none",
        user="10001:10001",
        read_only=True,
        tmpfs={"/tmp": "rw,size=67108864,uid=10001,gid=10001,mode=1777"},
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
    )
    try:
        container.start()
        code, output = container.exec_run(["base64", "/fixture/bun.lockb"])
        if code:
            raise RuntimeError(output.decode())
        Path(__file__).with_name("bun.lockb").write_bytes(base64.b64decode(output))
    finally:
        container.remove(force=True)
