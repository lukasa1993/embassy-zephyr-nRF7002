#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/_common.sh"
BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --board) [ "$#" -ge 2 ] || die "--board requires a value"; BOARD=$2; shift ;;
    --profile) [ "$#" -ge 2 ] || die "--profile requires a value"; PROFILE=$2; shift ;;
    *) die "usage: status.sh [--board BOARD] [--profile PROFILE]" ;;
  esac
  shift
done
validate_board_profile "$BOARD" "$PROFILE"
ARTIFACT=$(artifact_dir "$BOARD" "$PROFILE")
printf '%s\n' "zephyr root: $ZEPHYR_ROOT"
printf '%s\n' "board/profile: $BOARD / $PROFILE"
printf '%s\n' "docker platform: $DOCKER_PLATFORM"
printf '%s\n' "NCS: $NCS_RELEASE ($NCS_REVISION)"
printf '%s\n' "Rust module: $RUST_MODULE_REVISION"
[ -f "$ZEPHYR_ROOT/.workspace/.west/config" ] && printf '%s\n' "west workspace: initialized" || printf '%s\n' "west workspace: missing"
[ -d "$(build_dir "$BOARD" "$PROFILE")" ] && printf '%s\n' "build: present" || printf '%s\n' "build: missing"
if [ -f "$ARTIFACT/manifest.json" ]; then
  "$SCRIPT_DIR/verify.sh" --for-rust --board "$BOARD" --profile "$PROFILE" || true
else
  printf '%s\n' "artifact: not packaged"
fi
