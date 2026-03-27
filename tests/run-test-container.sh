#!/bin/bash
# Build and run the test suite in a container.
# for testing linux kernel modules in a container running on macOS

set -euo pipefail

IMAGE_NAME="exsocks-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Building test suite image..."
docker build -f "${PROJECT_ROOT}/Dockerfile.test" -t "${IMAGE_NAME}" "${PROJECT_ROOT}"

echo "==> Running tests suite in container..."
# --privileged grants the container full access to the host kernel
#
# -v /lib/modules:/lib/modules:ro mounts the host VM's kernel module directory
# into the container so that modprobe can locate and load kernel modules.
docker run --rm \
  --privileged \
  --network host \
  -v /lib/modules:/lib/modules:ro \
  "${IMAGE_NAME}"
