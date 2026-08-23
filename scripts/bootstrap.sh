#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

usage() {
  cat >&2 <<'EOF'
usage: scripts/bootstrap.sh [--rebuild-image] [--no-update]

Build the pinned linux/amd64 toolchain image when necessary, initialize the
west workspace below zephyr/.workspace, and fetch the locked NCS/Rust module
projects inside the container.
EOF
}

WEST_UPDATE=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --rebuild-image)
      FORCE_IMAGE_BUILD=1
      export FORCE_IMAGE_BUILD
      ;;
    --no-update)
      WEST_UPDATE=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown option: $1"
      ;;
  esac
  shift
done

prepare_state_dirs
ensure_docker_image

image=$(docker_image_ref)
uid=$(id -u)
gid=$(id -g)

docker run --rm \
  --platform "$DOCKER_PLATFORM" \
  --entrypoint /bin/sh \
  --user "$uid:$gid" \
  --env "WEST_UPDATE=$WEST_UPDATE" \
  --env "HOME=/workspace/zephyr/.workspace/home" \
  --env "CARGO_HOME=/workspace/zephyr/.workspace/cargo" \
  --env "RUSTUP_HOME=/opt/rust/rustup" \
  --volume "$ZEPHYR_ROOT:/workspace/zephyr" \
  "$image" \
  /workspace/zephyr/scripts/container-bootstrap.sh
