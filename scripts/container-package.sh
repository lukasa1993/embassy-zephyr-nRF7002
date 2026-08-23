#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/_common.sh"

BOARD=${BOARD:-$DEFAULT_BOARD}
PROFILE=${PROFILE:-$DEFAULT_PROFILE}
SYSBUILD=${SYSBUILD:-$DEFAULT_SYSBUILD}
validate_board_profile "$BOARD" "$PROFILE"

BUILD_ROOT="$ZEPHYR_ROOT/.build/$BOARD/$PROFILE"
ARTIFACT="$ZEPHYR_ROOT/artifacts/$BOARD/$PROFILE"
[ -d "$BUILD_ROOT" ] || die "build output is missing: $BUILD_ROOT"
: "${ZEPHYR_LINKER:=arm-zephyr-eabi-gcc}"

# Compute the foundation closure with the same host/container helper used by
# verify.sh. Rust implementation sources and Cargo lockfiles are intentionally
# outside this hash; they are rebuilt by the Rust-only loop.
INPUT_HASH=$(source_closure_sha256)

# Keep packaging inside the pinned image too. Python is used here only for
# deterministic filesystem walking and JSON emission; no host interpreter is
# involved in the Zephyr workflow.
python3 - "$ZEPHYR_ROOT" "$BUILD_ROOT" "$ARTIFACT" "$BOARD" "$PROFILE" "$SYSBUILD" \
  "$INPUT_HASH" "$NCS_RELEASE" "$NCS_REVISION" "$ZEPHYR_REVISION" \
  "$RUST_MODULE_REVISION" "$TOOLCHAIN_IMAGE_DIGEST" "$RUST_TARGET" \
  "$RUST_TOOLCHAIN" "$ZEPHYR_LINKER" <<'PY'
import datetime
import hashlib
import json
import shutil
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
build_root = Path(sys.argv[2]).resolve()
artifact = Path(sys.argv[3]).resolve()
board = sys.argv[4]
profile = sys.argv[5]
sysbuild = sys.argv[6] == "1"
input_hash = sys.argv[7]
ncs_release = sys.argv[8]
ncs_revision = sys.argv[9]
zephyr_revision = sys.argv[10]
rust_module_revision = sys.argv[11]
toolchain_image_digest = sys.argv[12]
target_triple = sys.argv[13]
rust_toolchain = sys.argv[14]
linker = sys.argv[15]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_zephyr_build(path: Path) -> bool:
    markers = (
        path / "include/generated/zephyr/autoconf.h",
        path / "include/generated/autoconf.h",
        path / "zephyr/include/generated/zephyr/autoconf.h",
    )
    return any(marker.is_file() for marker in markers)


candidate_paths = [build_root / "zephyr", build_root]
if build_root.is_dir():
    candidate_paths.extend(sorted((p for p in build_root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts)))
image_build = next((p for p in candidate_paths if p.exists() and is_zephyr_build(p)), None)
if image_build is None:
    raise SystemExit(
        f"package: cannot find a Zephyr image build below {build_root}; "
        "sysbuild usually places it in .build/<board>/<profile>/zephyr"
    )


artifact.mkdir(parents=True, exist_ok=True)

# A package is additive and hash-addressed by its manifest. We intentionally do
# not delete an older artifact tree here: an interrupted package remains
# recoverable, and verify.sh only trusts files listed by the new manifest.
files = {}
archives = []


def copy_file(source: Path, destination: Path, kind: str) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    relative = destination.relative_to(artifact).as_posix()
    files[relative] = {"path": relative, "sha256": sha256_file(destination), "kind": kind}
    return relative


def build_relative(source: Path) -> str:
    return source.relative_to(image_build).as_posix()


response_candidates = []
link_command_candidates = []
link_script_candidates = []

for source in sorted((p for p in image_build.rglob("*") if p.is_file()), key=lambda p: build_relative(p)):
    relative = build_relative(source)
    suffix = source.suffix.lower()
    name = source.name
    if suffix == ".a":
        archive_path = copy_file(source, artifact / "archives" / relative, "archive")
        # Preserve the original build-relative name under linker/ as well so a
        # response file which uses a relative archive path can be replayed.
        copy_file(source, artifact / "linker" / relative, "link-input")
        archives.append({"path": archive_path, "sha256": files[archive_path]["sha256"], "kind": "archive"})
        continue
    if suffix == ".o":
        copy_file(source, artifact / "objects" / relative, "object")
        copy_file(source, artifact / "linker" / relative, "link-input")
        continue
    if suffix == ".rsp":
        path = copy_file(source, artifact / "linker" / relative, "response")
        response_candidates.append((source, path))
        continue
    if name == "link.txt" or name.endswith("link command.txt"):
        path = copy_file(source, artifact / "linker" / relative, "link-command")
        link_command_candidates.append((source, path))
        continue
    if suffix in {".cmd", ".ld", ".lds"} or name.startswith("linker"):
        path = copy_file(source, artifact / "linker" / relative, "linker-script")
        link_script_candidates.append((source, path))
        continue
    parts = set(source.parts)
    if "generated" in parts or "include" in parts or name in {
        ".config",
        "zephyr.dts",
        "edt.pickle",
        "autoconf.h",
        "offsets.h",
        "devicetree_generated.h",
    }:
        copy_file(source, artifact / "generated" / relative, "generated")


if not archives:
    raise SystemExit("package: no .a archives were found in the Zephyr image build")


def text_contains(path: Path, needles) -> bool:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return False
    return all(needle in text for needle in needles)


selected_response = None
for source, relative in response_candidates:
    if text_contains(source, ("libzephyr.a",)):
        selected_response = (source, relative)
        break
if selected_response is None and response_candidates:
    selected_response = response_candidates[0]
# A response file is optional evidence from the captured Zephyr build. It is
# never treated as a standalone Rust linker input: the supported relink path is
# Zephyr's own persistent CMake/Ninja build and official rust_cargo_application
# integration.


selected_link_command = None
for source, relative in link_command_candidates:
    if text_contains(source, ("libzephyr.a",)):
        selected_link_command = (source, relative)
        break
if selected_link_command is None and link_command_candidates:
    selected_link_command = link_command_candidates[0]

selected_link_script = None
# Prefer Zephyr's final generated linker.cmd.  A sysbuild contains many
# generated .ld fragments (for example app_data_alignment.ld); those are
# packaged as link inputs too, but the manifest's named linker script must
# identify the final script rather than an arbitrary fragment.
for source, relative in link_script_candidates:
    if source.name == "linker.cmd":
        selected_link_script = (source, relative)
        break
if selected_link_script is None and link_script_candidates:
    selected_link_script = link_script_candidates[0]


def first_named(*names):
    for name in names:
        for candidate in (image_build / name, image_build / "zephyr" / name):
            if candidate.is_file():
                return candidate
    return None


kconfig = first_named(".config")
dts = first_named("zephyr.dts")
lock_file = root / "west-lock.yml"
source_lock_hash = sha256_file(lock_file) if lock_file.is_file() else ""
kconfig_path = "generated/" + build_relative(kconfig) if kconfig else ""
dts_path = "generated/" + build_relative(dts) if dts else ""
link_response_path = selected_response[1] if selected_response else ""
link_response_hash = files[link_response_path]["sha256"] if link_response_path else ""
link_command_path = selected_link_command[1] if selected_link_command else ""
link_command_hash = files[link_command_path]["sha256"] if link_command_path else ""
link_script_path = selected_link_script[1] if selected_link_script else ""
link_script_hash = files[link_script_path]["sha256"] if link_script_path else ""


def package_path(path: Path) -> str:
    return path.relative_to(artifact).as_posix() if path else ""


manifest = {
    "schema": 1,
    "abi_version": "zephyr-foundation-v1",
    "package_role": "cached-zephyr-foundation",
    "relink_mode": "official-zephyr-cmake",
    "standalone_link_supported": "false",
    "build_tree_required": "true",
    "board": board,
    "profile": profile,
    "image": profile,
    "sysbuild": sysbuild,
    "ncs_release": ncs_release,
    "ncs_revision": ncs_revision,
    "zephyr_revision": zephyr_revision,
    "rust_module_revision": rust_module_revision,
    "toolchain_image_digest": toolchain_image_digest,
    "target_triple": target_triple,
    "rust_toolchain": rust_toolchain,
    "source_lock_sha256": source_lock_hash,
    "input_sha256": input_hash,
    "kconfig_path": kconfig_path,
    "kconfig_sha256": sha256_file(kconfig) if kconfig else "",
    "dts_path": dts_path,
    "dts_sha256": sha256_file(dts) if dts else "",
    "linker": linker,
    "link_response_path": link_response_path,
    "link_response_sha256": link_response_hash,
    "link_command_path": link_command_path,
    "link_command_sha256": link_command_hash,
    "link_script_path": link_script_path,
    "link_script_sha256": link_script_hash,
    "build_dir": build_relative(image_build),
    "built_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    "archive_ordering": "path-sorted-capture",
    "archives": sorted(archives, key=lambda entry: entry["path"]),
    "files": sorted(files.values(), key=lambda entry: entry["path"]),
}

for order, entry in enumerate(manifest["archives"]):
    # Deterministic package ordering only; this is deliberately not a linker
    # order and must not be used to relink outside Zephyr's build tree.
    entry["order"] = order


def one_line_object(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


ordered_scalar_keys = [
    "schema",
    "abi_version",
    "package_role",
    "relink_mode",
    "standalone_link_supported",
    "build_tree_required",
    "board",
    "profile",
    "image",
    "sysbuild",
    "ncs_release",
    "ncs_revision",
    "zephyr_revision",
    "rust_module_revision",
    "toolchain_image_digest",
    "target_triple",
    "rust_toolchain",
    "source_lock_sha256",
    "input_sha256",
    "kconfig_path",
    "kconfig_sha256",
    "dts_path",
    "dts_sha256",
    "linker",
    "link_response_path",
    "link_response_sha256",
    "link_command_path",
    "link_command_sha256",
    "link_script_path",
    "link_script_sha256",
    "build_dir",
    "built_at",
    "archive_ordering",
]
lines = ["{"]
for key in ordered_scalar_keys:
    suffix = ","
    lines.append(f"  {json.dumps(key)}: {json.dumps(manifest[key])}{suffix}")
lines.append('  "archives": [')
for index, entry in enumerate(manifest["archives"]):
    comma = "," if index + 1 < len(manifest["archives"]) else ""
    lines.append(f"    {one_line_object(entry)}{comma}")
lines.append("  ],")
lines.append('  "files": [')
for index, entry in enumerate(manifest["files"]):
    comma = "," if index + 1 < len(manifest["files"]) else ""
    lines.append(f"    {one_line_object(entry)}{comma}")
lines.append("  ]")
lines.append("}")
(artifact / "manifest.json").write_text("\n".join(lines) + "\n")
(artifact / ".input-sha256").write_text(input_hash + "\n")
(artifact / "artifact.env").write_text(
    "BOARD=" + board + "\n"
    + "PROFILE=" + profile + "\n"
    + "TARGET_TRIPLE=thumbv8m.main-none-eabihf\n"
    + "MANIFEST=manifest.json\n"
    + "INPUT_SHA256=" + input_hash + "\n"
    + "LINK_RESPONSE=" + link_response_path + "\n"
)

print(f"package: {artifact}")
print(f"package: Zephyr image build {image_build}")
print(f"package: {len(archives)} archives, {len(files)} packaged files")
PY
