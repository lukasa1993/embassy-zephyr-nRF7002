# Static verification

The native crate is checked with these commands:

```sh
cargo fmt --manifest-path native/Cargo.toml --all -- --check
cargo test --manifest-path native/Cargo.toml --all-features
cargo clippy --manifest-path native/Cargo.toml --all-targets --all-features -- -D warnings
cargo check --manifest-path native/Cargo.toml --no-default-features
```

These checks cover Rust formatting, type checking, unit tests, lint checks, the Embassy network adapter, and the `no_std` core feature set.

They do not prove RF operation. Hardware verification needs an nRF5340 plus nRF7002 board, the exact Nordic firmware image used by the ABI implementation, and a controlled access point.
