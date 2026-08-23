#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
SYSBUILD=${SYSBUILD:-$DEFAULT_SYSBUILD}
PRISTINE=${PRISTINE:-auto}
RUST_ONLY=${RUST_ONLY:-0}

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
    --pristine)
      [ "$#" -ge 2 ] || die "--pristine requires auto, always, or never"
      PRISTINE=$2
      shift
      ;;
    --rust-only)
      RUST_ONLY=1
      ;;
    -h|--help)
      printf '%s\n' "container-build: see scripts/build.sh --help"
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      die "unknown build option '$1' (put CMake arguments after --)"
      ;;
  esac
  shift
done

validate_board_profile "$BOARD" "$PROFILE"
case "$SYSBUILD" in
  0|1) ;;
  *) die "SYSBUILD must be 0 or 1" ;;
esac
case "$PRISTINE" in
  auto|always|never) ;;
  *) die "PRISTINE must be auto, always, or never" ;;
esac
case "$RUST_ONLY" in
  0|1) ;;
  *) die "RUST_ONLY must be 0 or 1" ;;
esac

WEST_WORKSPACE="$ZEPHYR_ROOT/.workspace"
BUILD_ROOT="$ZEPHYR_ROOT/.build/$BOARD/$PROFILE"
APP_DIR="$ZEPHYR_ROOT/app"
if [ ! -d "$APP_DIR" ] && [ -d "$ZEPHYR_ROOT/rust/app" ]; then
  APP_DIR="$ZEPHYR_ROOT/rust/app"
fi

[ -f "$WEST_WORKSPACE/.west/config" ] || die "west workspace is missing; run scripts/container-bootstrap.sh"
[ -d "$APP_DIR" ] || die "application directory is missing: $APP_DIR"

if [ "$RUST_ONLY" = "1" ]; then
  [ -f "$BUILD_ROOT/CMakeCache.txt" ] || die "Rust-only build needs an existing foundation at $BUILD_ROOT; run build.sh first"
  [ -f "$BUILD_ROOT/build.ninja" ] || die "Rust-only build needs an existing Ninja foundation at $BUILD_ROOT; run build.sh first"
  "$ZEPHYR_ROOT/scripts/check-invariants.sh" --for-rust --board "$BOARD" --profile "$PROFILE"
  PRISTINE=never
fi

mkdir -p "$BUILD_ROOT"
cd "$WEST_WORKSPACE"

if [ "$RUST_ONLY" = "1" ]; then
  # The foundation is already configured. Calling west here would re-enter
  # CMake even when only Rust changed, so run the captured Ninja graph
  # directly. The target still performs Cargo, Zephyr's generated metadata,
  # and the normal final relink; it does not rebuild the C foundation.
  require_command ninja
  if [ "$SYSBUILD" = "1" ]; then
    # The outer sysbuild target is an ExternalProject target whose app-build
    # stamp is intentionally phony. Invoking it makes CMake revisit the whole
    # application graph on every run. Enter the already-configured application
    # image graph directly so a Rust edit cannot wake the C foundation.
    NINJA_ROOT="$BUILD_ROOT/app"
  else
    NINJA_ROOT="$BUILD_ROOT"
  fi
  [ -f "$NINJA_ROOT/build.ninja" ] || die "Rust-only Ninja graph is missing: $NINJA_ROOT/build.ninja"
  NINJA_TARGET=zephyr/zephyr.elf

  RUST_GUARD_DIR=$(mktemp -d "$BUILD_ROOT/.rust-only-guard.XXXXXX")
  trap 'rm -rf "$RUST_GUARD_DIR"' 0 1 2 3 15

  snapshot_cmake_metadata() {
    output=$1
    : > "$output"
    for candidate in \
      "$BUILD_ROOT/CMakeCache.txt" \
      "$BUILD_ROOT/build.ninja" \
      "$BUILD_ROOT/app/CMakeCache.txt" \
      "$BUILD_ROOT/app/build.ninja" \
      "$BUILD_ROOT/zephyr/CMakeCache.txt" \
      "$BUILD_ROOT/zephyr/build.ninja"; do
      if [ -f "$candidate" ]; then
        printf '%s|' "$candidate" >> "$output"
        stat -c '%Y:%s' "$candidate" >> "$output"
      fi
    done
  }

  # Build-generated C inputs (ISR tables, offsets, linker metadata, and the
  # Rust wrapper) are intentionally not included; a Rust-only relink may
  # regenerate those metadata objects. Ninja stores compiler dependency data
  # in its binary .ninja_deps database, so classify the generated object paths
  # instead of relying on optional per-object .d files. Any other C object
  # changing is a hard failure because it means the checked-out app, Zephyr,
  # NCS, or module foundation was not actually reused.
  snapshot_checked_c_objects() {
    output=$1
    : > "$output"
    find "$BUILD_ROOT" -type f \( -name '*.obj' -o -name '*.o' \) -print 2>/dev/null | sort | while IFS= read -r object; do
      case "$object" in
        */misc/generated/*|*/isr_tables*|*/offsets*|*/linker*|*/rust_app/*|*/zephyr_final.dir/*|*/zephyr_pre*.dir/*)
          continue
          ;;
      esac
      printf '%s|' "$object"
      stat -c '%Y:%s' "$object"
      sha256sum "$object" | awk '{print $1}'
    done > "$output"
  }

  snapshot_cmake_metadata "$RUST_GUARD_DIR/cmake.before"
  snapshot_checked_c_objects "$RUST_GUARD_DIR/c-objects.before"

  ninja -C "$NINJA_ROOT" "$NINJA_TARGET"

  snapshot_cmake_metadata "$RUST_GUARD_DIR/cmake.after"
  snapshot_checked_c_objects "$RUST_GUARD_DIR/c-objects.after"
  if ! cmp -s "$RUST_GUARD_DIR/cmake.before" "$RUST_GUARD_DIR/cmake.after"; then
    die "Rust-only rebuild regenerated CMake metadata; run a full foundation build"
  fi
  if ! cmp -s "$RUST_GUARD_DIR/c-objects.before" "$RUST_GUARD_DIR/c-objects.after"; then
    die "Rust-only rebuild recompiled a checked-out C source; run a full foundation build"
  fi
  trap - 0 1 2 3 15
  rm -rf "$RUST_GUARD_DIR"
else
  if [ "$SYSBUILD" = "1" ]; then
    west build \
      --sysbuild \
      --pristine="$PRISTINE" \
      --build-dir "$BUILD_ROOT" \
      --board "$BOARD" \
      "$APP_DIR" \
      -- "$@"
  else
    west build \
      --pristine="$PRISTINE" \
      --build-dir "$BUILD_ROOT" \
      --board "$BOARD" \
      "$APP_DIR" \
      -- "$@"
  fi
fi

# This file is convenience metadata only. The packaged manifest generated by
# package.sh remains the source of truth for Rust relinks.
{
  printf '%s\n' "board=$BOARD"
  printf '%s\n' "profile=$PROFILE"
  printf '%s\n' "sysbuild=$SYSBUILD"
  printf '%s\n' "pristine=$PRISTINE"
  printf '%s\n' "rust_only=$RUST_ONLY"
  printf '%s\n' "build_dir=$BUILD_ROOT"
  printf '%s\n' "app_dir=$APP_DIR"
  printf '%s\n' "ncs_release=$NCS_RELEASE"
  printf '%s\n' "ncs_revision=$NCS_REVISION"
  printf '%s\n' "rust_module_revision=$RUST_MODULE_REVISION"
  printf '%s\n' "rust_target=$RUST_TARGET"
} > "$BUILD_ROOT/build.env"

"$ZEPHYR_ROOT/scripts/check-invariants.sh" --for-rust --board "$BOARD" --profile "$PROFILE"

printf '%s\n' "zephyr: build complete at $BUILD_ROOT"
