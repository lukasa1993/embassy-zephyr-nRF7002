#!/bin/sh
set -eu

# Verify the fixed Rust-controlled Wi-Fi foundation contract. This script is deliberately
# host/container agnostic: it only reads generated build files and checked-in
# sources.  It never invokes west, CMake, Docker, Cargo, or a linker.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
FOR_RUST=0
CONFIG_OVERRIDE=

usage() {
  cat >&2 <<'EOF'
usage: scripts/check-invariants.sh [options]

Options:
  --board BOARD       board used for the generated build
  --profile PROFILE   profile used for the generated build
  --config PATH       check this final .config (artifact/package mode)
  --for-rust          require a reusable foundation suitable for Rust-only
  -h, --help          show this help
EOF
}

fail_invariant() {
  printf '%s\n' "zephyr: foundation invariant failed: $*" >&2
  printf '%s\n' "zephyr: rebuild the pinned foundation with scripts/build.sh" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --board)
      [ "$#" -ge 2 ] || fail_invariant "--board requires a value"
      BOARD=$2
      shift
      ;;
    --profile)
      [ "$#" -ge 2 ] || fail_invariant "--profile requires a value"
      PROFILE=$2
      shift
      ;;
    --config)
      [ "$#" -ge 2 ] || fail_invariant "--config requires a value"
      CONFIG_OVERRIDE=$2
      shift
      ;;
    --for-rust)
      FOR_RUST=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      fail_invariant "unknown option: $1"
      ;;
  esac
  shift
done

validate_board_profile "$BOARD" "$PROFILE"

config_value() {
  key=$1
  awk -v key="CONFIG_$key" '
    $0 == key "=y" { value = "y"; found = 1; next }
    $0 == key "=m" { value = "m"; found = 1; next }
    $0 == key "=n" { value = "n"; found = 1; next }
    $0 == "# " key " is not set" { value = "n"; found = 1; next }
    $0 ~ "^" key "=" {
      raw = $0
      sub("^" key "=", "", raw)
      value = raw
      found = 1
      next
    }
    END {
      if (!found) {
        print ""
      } else {
        print value
      }
    }
  ' "$CONFIG"
}

require_enabled() {
  key=$1
  value=$(config_value "$key")
  [ "$value" = y ] || fail_invariant "$CONFIG: CONFIG_$key must be enabled (got '${value:-missing}')"
}

require_disabled() {
  key=$1
  value=$(config_value "$key")
  case "$value" in
    y|m)
      fail_invariant "$CONFIG: CONFIG_$key must be disabled (got '$value')"
      ;;
  esac
}

require_value() {
  key=$1
  expected=$2
  value=$(config_value "$key")
  [ "$value" = "$expected" ] || fail_invariant "$CONFIG: CONFIG_$key must equal '$expected' (got '${value:-missing}')"
}

require_nonzero() {
  key=$1
  value=$(config_value "$key")
  case "$value" in
    ''|*[!0-9]*)
      fail_invariant "$CONFIG: CONFIG_$key must be a nonzero integer (got '${value:-missing}')"
      ;;
  esac
  [ "$value" -gt 0 ] || fail_invariant "$CONFIG: CONFIG_$key must be nonzero"
}

check_pure_l2_config() {
  # These are the only address/transport services allowed to be absent from
  # the foundation.  Hidden derived symbols are accepted when Kconfig omits
  # them entirely; an explicit y/m still fails closed.
  for key in \
    NET_IPV4 NET_IPV6 NET_NATIVE_IPV4 NET_NATIVE_IPV6 NET_NATIVE_IP \
    NET_TCP NET_UDP NET_DHCPV4 NET_DHCPV6 DNS_RESOLVER \
    NET_CONFIG_AUTO_INIT NET_CONFIG_SETTINGS; do
    require_disabled "$key"
  done

  # CONFIG_NET_SOCKETS_PACKET is Zephyr's AF_PACKET/SOCK_RAW provider.  The
  # DGRAM variant is also required by hostap's EAPOL path; they are separate
  # socket types sharing one bounded L2 packet implementation.
  for key in \
    NETWORKING NET_SOCKETS NET_SOCKETS_PACKET NET_SOCKETS_PACKET_DGRAM \
    NET_L2_ETHERNET NET_L2_ETHERNET_MGMT NET_MGMT NET_MGMT_EVENT \
    NET_MGMT_EVENT_INFO WIFI WIFI_NRF70 WIFI_NM_WPA_SUPPLICANT \
    WIFI_USAGE_MODE_STA_AP WIFI_NM_WPA_SUPPLICANT_AP \
    WIFI_NM_WPA_SUPPLICANT_ROAMING \
    NRF70_STA_MODE NRF70_AP_MODE NRF70_ENABLE_DUAL_VIF \
    NET_STATISTICS NET_STATISTICS_USER_API NET_STATISTICS_WIFI \
    WIFI_READY_LIB RUST FPU CSPRNG_NEEDED \
    CSPRNG_ENABLED CONSOLE_GETCHAR; do
    require_enabled "$key"
  done

  require_disabled NRF_WIFI_IF_AUTO_START
  require_disabled NRF_WIFI_RPU_RECOVERY
  require_disabled WIFI_MGMT_TWT_CHECK_IP
  require_value WIFI_NM_MAX_MANAGED_INTERFACES 2
  require_value WIFI_MGMT_AP_MAX_NUM_STA 1
  require_value WIFI_MGMT_SCAN_CHAN_MAX_MANUAL 16
  require_value NET_L2_WIFI_MGMT_LOG_LEVEL 0
  require_disabled WIFI_NM_WPA_SUPPLICANT_DEBUG_SHOW_KEYS
  require_disabled DEBUG_COREDUMP
  require_nonzero CONSOLE_GETCHAR_BUFSIZE
}

check_no_ip_compat_guard() {
  no_ip_compat="$ZEPHYR_ROOT/app/src/no_ip_compat.c"
  [ -f "$no_ip_compat" ] || fail_invariant "missing pure-L2 multicast compatibility seam: $no_ip_compat"

  # This exact guard is a safety boundary.  If either native IP family is
  # enabled in a future profile, Zephyr's real multicast monitor must win.
  grep -Eq '#if[[:space:]]+!defined\(CONFIG_NET_NATIVE_IPV4\)[[:space:]]+&&[[:space:]]+!defined\(CONFIG_NET_NATIVE_IPV6\)' "$no_ip_compat" \
    || fail_invariant "no_ip_compat.c is not guarded by both native-IP symbols"
  for symbol in net_if_mcast_mon_register net_if_mcast_mon_unregister net_if_mcast_monitor; do
    grep -Eq "^[[:space:]]*(void|static[[:space:]]+void)[[:space:]]+$symbol[[:space:]]*\(" "$no_ip_compat" \
      || fail_invariant "no_ip_compat.c no longer defines $symbol"
  done
}

find_final_config() {
  build_root=$1
  # Sysbuild puts the application image under app/; regular west builds put
  # it directly under the build root. Prefer the known locations, then find
  # the first Rust-enabled config as a compatibility fallback.
  for candidate in \
    "$build_root/app/zephyr/.config" \
    "$build_root/zephyr/.config" \
    "$build_root/.config"; do
    if [ -f "$candidate" ] && grep -q '^CONFIG_RUST=y$' "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  find "$build_root" -type f -name .config -print 2>/dev/null | while IFS= read -r candidate; do
    if grep -q '^CONFIG_RUST=y$' "$candidate"; then
      printf '%s\n' "$candidate"
      break
    fi
  done
}

find_final_elf() {
  build_root=$1
  for candidate in \
    "$build_root/app/zephyr/zephyr.elf" \
    "$build_root/zephyr/zephyr.elf"; do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  find "$build_root" -type f -name zephyr.elf -print 2>/dev/null | head -n 1
}

check_hard_float_abi() {
  build_root=$1
  rust_target_file=
  rust_target_file=$(find "$build_root" -type f -name sample-cargo-config.toml -print 2>/dev/null | head -n 1 || true)
  [ -n "$rust_target_file" ] || fail_invariant "Rust Cargo target configuration is missing below $build_root"
  grep -Fq "target = \"$RUST_TARGET\"" "$rust_target_file" \
    || fail_invariant "$rust_target_file does not select $RUST_TARGET"

  # The Rust target selects the hard-float ABI for rustc; also require the
  # captured Zephyr C flags to agree.  Check only generated text metadata, not
  # binary archives, so this remains quick and deterministic.
  abi_found=0
  for candidate in \
    "$build_root/build.ninja" \
    "$build_root/app/build.ninja" \
    "$build_root/zephyr/build.ninja" \
    "$build_root/app/compile_commands.json" \
    "$build_root/compile_commands.json" \
    "$build_root/app/CMakeCache.txt" \
    "$build_root/CMakeCache.txt"; do
    if [ -f "$candidate" ] && grep -Fq -- '-mfloat-abi=hard' "$candidate"; then
      abi_found=1
      break
    fi
  done
  [ "$abi_found" = 1 ] || fail_invariant "generated compiler metadata has no -mfloat-abi=hard flag"
}

if [ -n "$CONFIG_OVERRIDE" ]; then
  CONFIG=$CONFIG_OVERRIDE
  [ -f "$CONFIG" ] || fail_invariant "final .config is missing: $CONFIG"
  BUILD_ROOT=
else
  BUILD_ROOT=$(build_dir "$BOARD" "$PROFILE")
  [ -d "$BUILD_ROOT" ] || fail_invariant "foundation build is missing: $BUILD_ROOT"
  CONFIG=$(find_final_config "$BUILD_ROOT")
  [ -n "$CONFIG" ] || fail_invariant "Rust-enabled final .config is missing below $BUILD_ROOT"
fi

check_pure_l2_config
check_no_ip_compat_guard

if [ -n "${BUILD_ROOT:-}" ]; then
  elf=$(find_final_elf "$BUILD_ROOT")
  [ -n "$elf" ] || fail_invariant "final Zephyr ELF is missing below $BUILD_ROOT"

  if [ "$FOR_RUST" = 1 ]; then
    [ -f "$BUILD_ROOT/CMakeCache.txt" ] || fail_invariant "foundation CMakeCache.txt is missing"
    [ -f "$BUILD_ROOT/build.ninja" ] || fail_invariant "foundation build.ninja is missing"
    rust_archive=$(find "$BUILD_ROOT" -type f -name librustapp.a -print 2>/dev/null | head -n 1 || true)
    [ -n "$rust_archive" ] || fail_invariant "Rust staticlib is missing below $BUILD_ROOT"
    check_hard_float_abi "$BUILD_ROOT"
  fi
fi

if [ "$FOR_RUST" = 1 ]; then
  printf '%s\n' "zephyr: Rust-controlled STA/AP capability and pure-L2 foundation checks passed: $CONFIG"
else
  printf '%s\n' "zephyr: STA/AP capability and pure-L2 invariants passed: $CONFIG"
fi
