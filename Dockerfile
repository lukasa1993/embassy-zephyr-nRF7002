# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0
#
# The digest is deliberate. Do not change this to :latest or to an unpinned
# release tag: the Zephyr foundation ABI is tied to the complete toolchain.
FROM --platform=linux/amd64 ghcr.io/nrfconnect/sdk-nrf-toolchain:v3.4.0@sha256:f1dca44678dae83e37404e33f369786f5b2ffe2ed497eec1815f66c3a868bace

ARG RUST_TOOLCHAIN=1.95.0
ARG RUST_TARGET=thumbv8m.main-none-eabihf

ENV DEBIAN_FRONTEND=noninteractive \
    NCS_TOOLCHAIN_BUNDLE=fbf7391cab \
    RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    RUST_TOOLCHAIN=${RUST_TOOLCHAIN} \
    RUST_TARGET=${RUST_TARGET} \
    BINDGEN_EXTRA_CLANG_ARGS=-D__UINT32_C\(x\)=x##U \
    PATH=/opt/ncs/toolchains/fbf7391cab/usr/bin:/opt/ncs/toolchains/fbf7391cab/usr/local/bin:/opt/ncs/toolchains/fbf7391cab/opt/bin:/opt/ncs/toolchains/fbf7391cab/nrfutil/bin:/opt/ncs/toolchains/fbf7391cab/opt/zephyr-sdk/gnu/arm-zephyr-eabi/bin:/opt/ncs/toolchains/fbf7391cab/opt/zephyr-sdk/gnu/riscv64-zephyr-elf/bin:/opt/rust/cargo/bin:${PATH} \
    LD_LIBRARY_PATH=/opt/ncs/toolchains/fbf7391cab/usr/lib:/opt/ncs/toolchains/fbf7391cab/usr/lib/x86_64-linux-gnu:/opt/ncs/toolchains/fbf7391cab/usr/local/lib \
    PYTHONHOME=/opt/ncs/toolchains/fbf7391cab/usr/local \
    PYTHONPATH=/opt/ncs/toolchains/fbf7391cab/usr/local/lib/python3.12:/opt/ncs/toolchains/fbf7391cab/usr/local/lib/python3.12/site-packages \
    ZEPHYR_TOOLCHAIN_VARIANT=zephyr/gnu \
    ZEPHYR_SDK_INSTALL_DIR=/opt/ncs/toolchains/fbf7391cab/opt/zephyr-sdk \
    GIT_EXEC_PATH=/opt/ncs/toolchains/fbf7391cab/usr/local/libexec/git-core \
    GIT_TEMPLATE_DIR=/opt/ncs/toolchains/fbf7391cab/usr/local/share/git-core/templates

# NCS toolchain images provide west, CMake, Python, Git, and the Nordic
# compiler. They intentionally do not contain the NCS/Zephyr source checkout;
# bootstrap.sh fetches that pinned source closure into the persistent
# .workspace bind mount. Install the Rust compiler and bindgen prerequisites
# here (never on the host) because the official Zephyr Rust module invokes
# Cargo and clang as part of the Zephyr build.
RUN set -eu; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
      ca-certificates curl libnghttp2-14 clang libclang-dev; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /opt/rust/cargo /opt/rust/rustup; \
    python3 -c 'import urllib.request; urllib.request.urlretrieve("https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init", "/opt/rust/rustup-init")'; \
    chmod 0755 /opt/rust/rustup-init; \
    /opt/rust/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_TOOLCHAIN}" --target "${RUST_TARGET}"; \
    /opt/rust/cargo/bin/rustup toolchain install "${RUST_TOOLCHAIN}" \
      --profile minimal --target "${RUST_TARGET}"; \
    /opt/rust/cargo/bin/rustc --version; \
    /opt/rust/cargo/bin/cargo --version; \
    west --version; \
    cmake --version | sed -n '1p'; \
    python3 --version

# Metadata is copied only for image self-description. At runtime all checked
# out source and generated state is bind-mounted from the repository.
WORKDIR /workspace/zephyr
COPY west.yml west-lock.yml /opt/embassy-zephyr-nrf7002/
COPY scripts /opt/embassy-zephyr-nrf7002/scripts

CMD ["/bin/sh"]
