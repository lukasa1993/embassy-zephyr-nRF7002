#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
FOR_RUST=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --for-rust) FOR_RUST=1 ;;
    --board) [ "$#" -ge 2 ] || die "--board requires a value"; BOARD=$2; shift ;;
    --profile) [ "$#" -ge 2 ] || die "--profile requires a value"; PROFILE=$2; shift ;;
    -h|--help) printf '%s\n' "usage: verify.sh [--for-rust] [--board BOARD] [--profile PROFILE]"; exit 0 ;;
    *) die "unknown verification option '$1'" ;;
  esac
  shift
done

fail_verification() {
  printf '%s\n' "zephyr: foundation verification failed: $*" >&2
  printf '%s\n' "zephyr: run scripts/bootstrap.sh, scripts/build.sh, and scripts/package.sh explicitly" >&2
  exit 1
}

archive_tmp=
file_tmp=
cleanup() {
  [ -z "${archive_tmp:-}" ] || rm -f "$archive_tmp"
  [ -z "${file_tmp:-}" ] || rm -f "$file_tmp"
}
trap cleanup EXIT HUP INT TERM

valid_sha256() {
  value=$1
  case "$value" in
    ''|*[!0123456789abcdefABCDEF]*) return 1 ;;
  esac
  [ "${#value}" -eq 64 ]
}

expect_hash_scalar() {
  key=$1
  value=$(manifest_scalar "$key")
  valid_sha256 "$value" || fail_verification "$key is not a SHA-256 digest"
}

validate_board_profile "$BOARD" "$PROFILE"
ARTIFACT=$(artifact_dir "$BOARD" "$PROFILE")
MANIFEST="$ARTIFACT/manifest.json"
[ -d "$ARTIFACT" ] || fail_verification "artifact directory is missing: $ARTIFACT"
[ -f "$MANIFEST" ] || fail_verification "manifest is missing: $MANIFEST"
[ -f "$ARTIFACT/.input-sha256" ] || fail_verification "input hash is missing"

manifest_scalar() {
  key=$1
  sed -n "s/^[[:space:]]*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[,]*[[:space:]]*$/\1/p" "$MANIFEST" | head -n 1
}
manifest_number() {
  key=$1
  sed -n "s/^[[:space:]]*\"$key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[,]*[[:space:]]*$/\1/p" "$MANIFEST" | head -n 1
}
expect_scalar() {
  actual=$(manifest_scalar "$1")
  [ "$actual" = "$2" ] || fail_verification "$1 mismatch (expected '$2', got '${actual:-<missing>}')"
}

[ "$(manifest_number schema)" = 1 ] || fail_verification "unsupported manifest schema"
expect_scalar board "$BOARD"
expect_scalar profile "$PROFILE"
expect_scalar abi_version zephyr-foundation-v1
expect_scalar package_role cached-zephyr-foundation
expect_scalar relink_mode official-zephyr-cmake
expect_scalar standalone_link_supported false
expect_scalar build_tree_required true
expect_scalar image "$PROFILE"
expect_scalar ncs_release "$NCS_RELEASE"
expect_scalar ncs_revision "$NCS_REVISION"
expect_scalar zephyr_revision "$ZEPHYR_REVISION"
expect_scalar rust_module_revision "$RUST_MODULE_REVISION"
expect_scalar toolchain_image_digest "$TOOLCHAIN_IMAGE_DIGEST"
expect_scalar target_triple "$RUST_TARGET"
expect_scalar rust_toolchain "$RUST_TOOLCHAIN"
[ -f "$ZEPHYR_ROOT/west-lock.yml" ] || fail_verification "west-lock.yml is missing"
expect_hash_scalar source_lock_sha256
expect_hash_scalar input_sha256
expect_hash_scalar kconfig_sha256
expect_hash_scalar dts_sha256
expect_scalar archive_ordering path-sorted-capture

build_dir=$(manifest_scalar build_dir)
assert_safe_relative_metadata_path "$build_dir"

stored_input=$(sed -n '1p' "$ARTIFACT/.input-sha256")
[ -n "$stored_input" ] || fail_verification "empty .input-sha256"
valid_sha256 "$stored_input" || fail_verification ".input-sha256 is not a SHA-256 digest"
[ "$stored_input" = "$(manifest_scalar input_sha256)" ] || fail_verification "manifest/input hash mismatch"
[ "$stored_input" = "$(source_closure_sha256)" ] || fail_verification "foundation input closure is stale"

# A symlink in the package could redirect a manifest path outside the artifact
# root while still passing a normal -f/hash check. Packages are generated with
# regular files only, so reject symlinked files or directories before walking
# the manifest.
if find "$ARTIFACT" -type l -print -quit | grep -q .; then
  fail_verification "artifact contains a symlink"
fi

verify_entry() {
  line=$1
  required_kind=${2-}
  path=$(printf '%s\n' "$line" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
  expected=$(printf '%s\n' "$line" | sed -n 's/.*"sha256":"\([^"]*\)".*/\1/p')
  kind=$(printf '%s\n' "$line" | sed -n 's/.*"kind":"\([^"]*\)".*/\1/p')
  [ -n "$path" ] || return 0
  [ -n "$expected" ] || fail_verification "manifest entry has no hash"
  valid_sha256 "$expected" || fail_verification "manifest entry has an invalid SHA-256 hash: $path"
  [ -n "$kind" ] || fail_verification "manifest entry has no kind: $path"
  [ -z "$required_kind" ] || [ "$kind" = "$required_kind" ] || fail_verification "manifest archive has wrong kind: $path"
  assert_safe_relative_path "$path"
  file="$ARTIFACT/$path"
  [ -f "$file" ] || fail_verification "packaged file is missing: $path"
  [ ! -L "$file" ] || fail_verification "packaged file is a symlink: $path"
  [ "$(host_sha256 "$file")" = "$expected" ] || fail_verification "hash mismatch: $path"
}

archive_lines=$(sed -n '/^[[:space:]]*"archives"[[:space:]]*:[[:space:]]*\[/,/^[[:space:]]*\],/p' "$MANIFEST")
printf '%s\n' "$archive_lines" | grep '"path":"' >/dev/null 2>&1 || fail_verification "manifest contains no archives"
archive_tmp=$(mktemp "${TMPDIR:-/tmp}/embassy-zephyr-nrf7002-archives.XXXXXX")
printf '%s\n' "$archive_lines" > "$archive_tmp"
while IFS= read -r line; do
  case "$line" in
    *'"path":"'*'"sha256":"'*)
      order=$(printf '%s\n' "$line" | sed -n 's/.*"order":\([0-9][0-9]*\).*/\1/p')
      [ -n "$order" ] || fail_verification "manifest archive has no deterministic order"
      verify_entry "$line" archive
      ;;
  esac
done < "$archive_tmp"

file_lines=$(sed -n '/^[[:space:]]*"files"[[:space:]]*:[[:space:]]*\[/,/^[[:space:]]*\]/p' "$MANIFEST")
printf '%s\n' "$file_lines" | grep '"path":"' >/dev/null 2>&1 || fail_verification "manifest contains no files"
file_tmp=$(mktemp "${TMPDIR:-/tmp}/embassy-zephyr-nrf7002-files.XXXXXX")
printf '%s\n' "$file_lines" > "$file_tmp"
while IFS= read -r line; do
  case "$line" in *'"path":"'*'"sha256":"'*) verify_entry "$line";; esac
done < "$file_tmp"

# A package is consumed without rerunning Zephyr, so validate the packaged
# final configuration itself.  Sysbuild packages can contain more than one
# .config; select the Rust-enabled application image rather than the sysbuild
# coordinator config.
packaged_config=$(find "$ARTIFACT/generated" -type f -name .config -print 2>/dev/null | while IFS= read -r candidate; do
  if grep -q '^CONFIG_RUST=y$' "$candidate"; then
    printf '%s\n' "$candidate"
    break
  fi
done)
[ -n "$packaged_config" ] || fail_verification "packaged Rust-enabled final .config is missing"
if [ "$FOR_RUST" = 1 ]; then
  "$SCRIPT_DIR/check-invariants.sh" --config "$packaged_config" --for-rust
else
  "$SCRIPT_DIR/check-invariants.sh" --config "$packaged_config"
fi

verify_optional() {
  path=$(manifest_scalar "$1")
  expected=$(manifest_scalar "$2")
  [ -n "$path" ] || { [ -z "$expected" ] || fail_verification "$2 set without $1"; return 0; }
  [ -n "$expected" ] || fail_verification "$1 has no hash"
  assert_safe_relative_path "$path"
  file="$ARTIFACT/$path"
  [ -f "$file" ] || fail_verification "packaged input is missing: $path"
  [ ! -L "$file" ] || fail_verification "packaged input is a symlink: $path"
  valid_sha256 "$expected" || fail_verification "$2 is not a SHA-256 digest"
  [ "$(host_sha256 "$file")" = "$expected" ] || fail_verification "hash mismatch: $path"
}

verify_required() {
  path=$(manifest_scalar "$1")
  [ -n "$path" ] || fail_verification "manifest has no $1"
  verify_optional "$1" "$2"
}

verify_required kconfig_path kconfig_sha256
verify_required dts_path dts_sha256
verify_optional link_response_path link_response_sha256
verify_optional link_command_path link_command_sha256
verify_required link_script_path link_script_sha256

if [ "$FOR_RUST" = 1 ]; then
  printf '%s\n' "zephyr: verified foundation for Rust-only rebuild: $ARTIFACT"
else
  printf '%s\n' "zephyr: verified foundation artifact: $ARTIFACT"
fi
