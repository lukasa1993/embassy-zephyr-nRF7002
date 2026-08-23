#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

WEST_WORKSPACE="$ZEPHYR_ROOT/.workspace"
MANIFEST_DIR="$WEST_WORKSPACE/manifest"

mkdir -p "$MANIFEST_DIR" "$WEST_WORKSPACE/cargo" "$WEST_WORKSPACE/home"

# west's local manifest is a copy so that west can treat .workspace as the
# workspace root. The checked-in source remains read-only in the image layer
# and changes are picked up on the next explicit bootstrap.
cp "$ZEPHYR_ROOT/west.yml" "$MANIFEST_DIR/west.yml"
cp "$ZEPHYR_ROOT/west-lock.yml" "$MANIFEST_DIR/west-lock.yml"

if [ ! -f "$WEST_WORKSPACE/.west/config" ]; then
  cd "$WEST_WORKSPACE"
  west init -l "$MANIFEST_DIR"
fi

cd "$WEST_WORKSPACE"
if [ "${WEST_UPDATE:-1}" = "1" ]; then
  west update
else
  printf '%s\n' "zephyr: west update skipped (--no-update)"
fi

# NCS has inactive optional projects that west intentionally leaves uncloned.
# Freeze the active build closure after the imports have been resolved. This
# also works with --no-update once a workspace has been bootstrapped.
west manifest --freeze --active-only > "$MANIFEST_DIR/west-frozen.yml"

# Freeze the complete imported NCS closure after west has resolved it. This is
# an audit artifact, not a second source of truth; west.yml/west-lock.yml stay
# authoritative and are included in the package input hash.
printf '%s\n' "zephyr: west workspace ready at $WEST_WORKSPACE"
printf '%s\n' "zephyr: NCS release $NCS_RELEASE ($NCS_REVISION)"
printf '%s\n' "zephyr: zephyr-lang-rust $RUST_MODULE_REVISION"
