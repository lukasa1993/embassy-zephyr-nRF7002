# Review checklist

- No Zephyr header, symbol, thread, work queue, timer, allocator, or network object is used by the native crate.
- Runtime code is `no_std` and forbids unsafe Rust.
- All shared-memory lengths, indexes, and address calculations are checked.
- Firmware segments are ordered, non-overlapping, bounded, and optionally CRC checked.
- Each status wait has a finite poll limit.
- Network buffers have fixed sizes and report invalid lengths.
- The Nordic codec and firmware release must be pinned together.
- RF operation is not accepted from mock tests alone.
