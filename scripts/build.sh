#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

usage() {
  cat >&2 <<'EOF'
usage: scripts/build.sh [--bootstrap] [build options]

Build the application with the pinned Zephyr/NCS toolchain inside Docker.
Build options are parsed in the container:
  --board BOARD       default: nrf7002dk/nrf5340/cpuapp
  --profile PROFILE   default: l2-underlay
  --sysbuild          use west build --sysbuild (default)
  --no-sysbuild       use a regular west build
  --pristine MODE     auto, always, or never (default: auto)
  --rust-only         reuse the existing CMake/Ninja foundation and rebuild
                      only the Cargo staticlib before Zephyr's normal relink
  -- [CMake args]     arguments passed after west's -- separator

--bootstrap is explicit: it runs the west bootstrap/update step first if the
workspace has not been initialized yet.
EOF
}

AUTO_BOOTSTRAP=0
if [ "${1-}" = "--bootstrap" ]; then
  AUTO_BOOTSTRAP=1
  shift
fi
if [ "${1-}" = "--help" ] || [ "${1-}" = "-h" ]; then
  usage
  exit 0
fi

prepare_state_dirs
ensure_docker_image

if [ ! -f "$ZEPHYR_ROOT/.workspace/.west/config" ]; then
  if [ "$AUTO_BOOTSTRAP" = "1" ]; then
    "$SCRIPT_DIR/bootstrap.sh"
  else
    die "west workspace is missing; run scripts/bootstrap.sh or scripts/build.sh --bootstrap"
  fi
fi

image=$(docker_image_ref)
uid=$(id -u)
gid=$(id -g)

docker run --rm \
  --platform "$DOCKER_PLATFORM" \
  --entrypoint /bin/sh \
  --user "$uid:$gid" \
  --env "HOME=/workspace/zephyr/.workspace/home" \
  --env "BINDGEN_EXTRA_CLANG_ARGS=-D__UINT32_C(x)=x##U" \
  --env "CARGO_HOME=/workspace/zephyr/.workspace/cargo" \
  --env "RUSTUP_HOME=/opt/rust/rustup" \
  --volume "$ZEPHYR_ROOT:/workspace/zephyr" \
  "$image" \
  /workspace/zephyr/scripts/container-build.sh "$@"
