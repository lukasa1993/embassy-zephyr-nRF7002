#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

VERSION=
BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}

usage() {
  cat >&2 <<'EOF'
usage: scripts/release-bundle.sh --version VERSION [--board BOARD] [--profile PROFILE]

Create release assets from an already-built and verified foundation. VERSION
must be a Git tag such as v0.1.0-alpha.1. Existing output is never overwritten.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION=$2
      shift
      ;;
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
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown release option '$1'"
      ;;
  esac
  shift
done

[ -n "$VERSION" ] || { usage; die "--version is required"; }
validate_component version "$VERSION"
case "$VERSION" in
  v[0-9]*) ;;
  *) die "version must start with 'v' followed by a digit" ;;
esac
validate_board_profile "$BOARD" "$PROFILE"

BUILD_ROOT=$(build_dir "$BOARD" "$PROFILE")
IMAGE_ROOT="$BUILD_ROOT/app/zephyr"
ARTIFACT=$(artifact_dir "$BOARD" "$PROFILE")
BOARD_SLUG=$(printf '%s' "$BOARD" | tr '/' '-')
OUTPUT="$ZEPHYR_ROOT/release/$VERSION"

[ ! -e "$OUTPUT" ] || die "release output already exists: $OUTPUT"
[ -f "$IMAGE_ROOT/zephyr.hex" ] || die "firmware hex is missing; run scripts/build.sh"
[ -f "$IMAGE_ROOT/zephyr.elf" ] || die "firmware ELF is missing; run scripts/build.sh"
[ -f "$IMAGE_ROOT/zephyr.bin" ] || die "firmware binary is missing; run scripts/build.sh"

"$SCRIPT_DIR/verify.sh" --for-rust --board "$BOARD" --profile "$PROFILE"

mkdir -p "$OUTPUT"
ASSET_PREFIX="embassy-zephyr-nrf7002-${BOARD_SLUG}-${VERSION}"
cp "$IMAGE_ROOT/zephyr.hex" "$OUTPUT/$ASSET_PREFIX.hex"
cp "$IMAGE_ROOT/zephyr.elf" "$OUTPUT/$ASSET_PREFIX.elf"
cp "$IMAGE_ROOT/zephyr.bin" "$OUTPUT/$ASSET_PREFIX.bin"

FOUNDATION_ASSET="$OUTPUT/$ASSET_PREFIX-foundation.tar.gz"
FOUNDATION_LIST=$(mktemp "${TMPDIR:-/tmp}/embassy-zephyr-nrf7002-release.XXXXXX")
trap 'rm -f "$FOUNDATION_LIST"' EXIT HUP INT TERM
{
  printf '%s\n' .input-sha256 artifact.env manifest.json
  sed -n 's/.*"path":"\([^"]*\)".*/\1/p' "$ARTIFACT/manifest.json"
} | LC_ALL=C sort -u > "$FOUNDATION_LIST"
tar -czf "$FOUNDATION_ASSET" -C "$ARTIFACT" -T "$FOUNDATION_LIST"
rm -f "$FOUNDATION_LIST"
trap - EXIT HUP INT TERM

CHECKSUMS="$OUTPUT/SHA256SUMS"
: > "$CHECKSUMS"
for asset in "$OUTPUT/$ASSET_PREFIX.hex" \
             "$OUTPUT/$ASSET_PREFIX.elf" \
             "$OUTPUT/$ASSET_PREFIX.bin" \
             "$FOUNDATION_ASSET"; do
  printf '%s  %s\n' "$(host_sha256 "$asset")" "$(basename -- "$asset")" >> "$CHECKSUMS"
done

printf '%s\n' "zephyr: release bundle written to $OUTPUT"
