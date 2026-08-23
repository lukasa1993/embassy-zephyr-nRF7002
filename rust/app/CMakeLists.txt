# SPDX-License-Identifier: MIT OR Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# This file is included by zephyr/app after it has found Zephyr and selected
# the board.  The parent application owns final linking; this subdirectory
# contributes only the Rust staticlib through the official module helper.
rust_cargo_application()
