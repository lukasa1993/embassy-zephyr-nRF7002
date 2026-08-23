cmake_minimum_required(VERSION 3.20.0)

# NCS v3.4 omits Zephyr's optional Rust project from its imported allowlist.
# Keep module discovery explicit in addition to the immutable west pin.
list(APPEND ZEPHYR_EXTRA_MODULES
  ${CMAKE_CURRENT_LIST_DIR}/../.workspace/modules/lang/rust
)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(embassy_zephyr_nrf7002_l2)

target_include_directories(app PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/../include
)

target_sources(app PRIVATE
  src/bridge.c
  src/wifi_control.c
  src/no_ip_compat.c
)

# This subdirectory contributes the reusable Cargo staticlib through the
# official integration. Zephyr remains final-link owner.
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../rust/app
                 ${CMAKE_CURRENT_BINARY_DIR}/rust_app)
