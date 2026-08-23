#!/bin/sh
# Shared path, identity, and host-only helpers. Callers set -eu before sourcing
# this file; no helper in here invokes west, CMake, Python, Cargo, or a linker.

COMMON_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ZEPHYR_ROOT=$(CDPATH= cd -- "$COMMON_SCRIPT_DIR/.." && pwd -P)
TOOLCHAIN_ENV="$ZEPHYR_ROOT/config/toolchain.env"

if [ -f "$TOOLCHAIN_ENV" ]; then
  # The file is checked in and contains simple NAME=value assignments only.
  # shellcheck disable=SC1090
  . "$TOOLCHAIN_ENV"
fi

: "${NCS_RELEASE:=v3.4.0}"
: "${NCS_REVISION:=99553055607b2e9885fbc80ccd11fa9da81c2df0}"
: "${ZEPHYR_REVISION:=ncs-v3.4.0}"
: "${RUST_MODULE_REVISION:=dd73abc242e995784da62352fe8c70d9a6c7ac2e}"
: "${RUST_TOOLCHAIN:=1.95.0}"
: "${RUST_TARGET:=thumbv8m.main-none-eabihf}"
: "${DOCKER_PLATFORM:=linux/amd64}"
: "${TOOLCHAIN_IMAGE:=ghcr.io/nrfconnect/sdk-nrf-toolchain:v3.4.0}"
: "${TOOLCHAIN_IMAGE_DIGEST:=sha256:f1dca44678dae83e37404e33f369786f5b2ffe2ed497eec1815f66c3a868bace}"
: "${DOCKER_IMAGE:=embassy-zephyr-nrf7002-foundation:ncs-v3.4.0}"
: "${DEFAULT_BOARD:=nrf7002dk/nrf5340/cpuapp}"
: "${DEFAULT_PROFILE:=l2-underlay}"
: "${DEFAULT_SYSBUILD:=1}"

die() {
  printf '%s\n' "zephyr: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is not installed"
}

prepare_state_dirs() {
  mkdir -p "$ZEPHYR_ROOT/.workspace" \
    "$ZEPHYR_ROOT/.workspace/home" \
    "$ZEPHYR_ROOT/.build" \
    "$ZEPHYR_ROOT/artifacts"
}

validate_component() {
  component_name=$1
  component_value=$2
  [ -n "$component_value" ] || die "$component_name must not be empty"
  case "$component_value" in
    /*|.|..|../*|*/../*)
      die "$component_name contains an unsafe path component: $component_value"
      ;;
  esac
}

validate_board_profile() {
  validate_component board "$1"
  validate_component profile "$2"
}

artifact_dir() {
  board=$1
  profile=$2
  validate_board_profile "$board" "$profile"
  printf '%s\n' "$ZEPHYR_ROOT/artifacts/$board/$profile"
}

build_dir() {
  board=$1
  profile=$2
  validate_board_profile "$board" "$profile"
  printf '%s\n' "$ZEPHYR_ROOT/.build/$board/$profile"
}

docker_image_ref() {
  if [ "${DOCKER_IMAGE_REF:-}" != "" ]; then
    printf '%s\n' "$DOCKER_IMAGE_REF"
  else
    printf '%s\n' "$DOCKER_IMAGE"
  fi
}

ensure_docker_image() {
  require_command docker
  image=$(docker_image_ref)
  if [ "${FORCE_IMAGE_BUILD:-0}" != "1" ] && docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  printf '%s\n' "zephyr: building pinned Docker image $image for $DOCKER_PLATFORM" >&2
  docker build \
    --pull \
    --platform "$DOCKER_PLATFORM" \
    --build-arg "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
    --build-arg "RUST_TARGET=$RUST_TARGET" \
    --tag "$image" \
    --file "$ZEPHYR_ROOT/Dockerfile" \
    "$ZEPHYR_ROOT"
}

host_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print $1}'
  else
    die "neither shasum nor sha256sum is installed; cannot verify a foundation artifact"
  fi
}

host_sha256_stdin() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    die "neither shasum nor sha256sum is installed; cannot verify a foundation artifact"
  fi
}

# Print the relative, sorted *foundation* source closure consumed by the package
# generator. Rust implementation sources, Cargo manifests, lockfiles, and
# target/ output are deliberately absent: they belong to the Rust-only rebuild
# and must not make a cached Zephyr foundation stale. The Rust/CMake integration
# file is included because changing it changes the Zephyr build graph.
#
# Newline-containing filenames are intentionally rejected: source paths in this
# repository are ordinary UTF-8 paths and a newline would make a human-readable
# manifest ambiguous.
closure_files() {
  old_lc_all=${LC_ALL-}
  LC_ALL=C
  export LC_ALL
  for root_file in Dockerfile .dockerignore .gitignore west.yml west-lock.yml; do
    [ -f "$ZEPHYR_ROOT/$root_file" ] && printf '%s\n' "$root_file"
  done
  for closure_file in \
    scripts/_common.sh \
    scripts/bootstrap.sh \
    scripts/container-bootstrap.sh \
    scripts/build.sh \
    scripts/container-build.sh \
    rust/app/CMakeLists.txt; do
    [ -f "$ZEPHYR_ROOT/$closure_file" ] && printf '%s\n' "$closure_file"
  done
  for closure_dir in config app include; do
    if [ -d "$ZEPHYR_ROOT/$closure_dir" ]; then
      find "$ZEPHYR_ROOT/$closure_dir" -type f \
        ! -path '*/.workspace/*' \
        ! -path '*/.build/*' \
        ! -path '*/artifacts/*' \
        ! -path '*/target/*' \
        ! -name '*.log' \
        -print | sed "s#^$ZEPHYR_ROOT/##"
    fi
  done
  LC_ALL=$old_lc_all
  export LC_ALL
}

source_closure_sha256() {
  closure_files | LC_ALL=C sort | while IFS= read -r relative_path; do
    [ -n "$relative_path" ] || continue
    [ -f "$ZEPHYR_ROOT/$relative_path" ] || continue
    digest=$(host_sha256 "$ZEPHYR_ROOT/$relative_path")
    printf '%s  %s\n' "$digest" "$relative_path"
  done | host_sha256_stdin
}

assert_safe_relative_path() {
  relative_path=$1
  case "$relative_path" in
    ''|/*|*\\*|*'//'*|/*/./*|*/../*|*/./|*/..|.|..)
      die "manifest contains an unsafe relative path: $relative_path"
      ;;
  esac
}

assert_safe_relative_metadata_path() {
  relative_path=$1
  [ "$relative_path" = "." ] && return 0
  assert_safe_relative_path "$relative_path"
}
