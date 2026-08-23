#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
SYSBUILD=${SYSBUILD:-$DEFAULT_SYSBUILD}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --board)
      [ "$#" -ge 2 ] || die "--board requires a value"
      BOARD=$2
      shift
      ;;
    --profile)
      [ "$#" -ge 2 ] || die "--profile requires a value"
      PROFILE=$2
      shift
      ;;
    --sysbuild)
      SYSBUILD=1
      ;;
    --no-sysbuild)
      SYSBUILD=0
      ;;
    -h|--help)
      printf '%s\n' "usage: scripts/package.sh [--board BOARD] [--profile PROFILE] [--sysbuild|--no-sysbuild]"
      exit 0
      ;;
    *)
      die "unknown package option '$1'"
      ;;
  esac
  shift
done

validate_board_profile "$BOARD" "$PROFILE"
prepare_state_dirs
ensure_docker_image

build_root=$(build_dir "$BOARD" "$PROFILE")
[ -d "$build_root" ] || die "build output is missing: $build_root; run scripts/build.sh first"

image=$(docker_image_ref)
uid=$(id -u)
gid=$(id -g)

docker run --rm \
  --platform "$DOCKER_PLATFORM" \
  --entrypoint /bin/sh \
  --user "$uid:$gid" \
  --env "HOME=/workspace/zephyr/.workspace/home" \
  --env "BOARD=$BOARD" \
  --env "PROFILE=$PROFILE" \
  --env "SYSBUILD=$SYSBUILD" \
  --env "CARGO_HOME=/workspace/zephyr/.workspace/cargo" \
  --env "RUSTUP_HOME=/opt/rust/rustup" \
  --volume "$ZEPHYR_ROOT:/workspace/zephyr" \
  "$image" \
  /workspace/zephyr/scripts/container-package.sh

printf '%s\n' "zephyr: package written to $(artifact_dir "$BOARD" "$PROFILE")"
