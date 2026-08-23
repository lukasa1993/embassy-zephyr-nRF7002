#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

# Fail on the host before starting Docker when the persistent Zephyr
# foundation is absent or does not satisfy the pure-L2 contract.  The actual
# rebuild is deliberately delegated to container-build.sh, which runs Ninja
# directly and guards against CMake regeneration or checked-out C sources
# being recompiled.
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
detect_board_profile() {
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
    esac
    shift
  done
}
detect_board_profile "$@"

"$SCRIPT_DIR/check-invariants.sh" --for-rust --board "$BOARD" --profile "$PROFILE"
exec "$SCRIPT_DIR/build.sh" --rust-only "$@"
