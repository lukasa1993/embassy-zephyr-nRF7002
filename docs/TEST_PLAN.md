# Native nRF7002 acceptance test plan

A native driver release is accepted only after the host tests and all applicable hardware tests pass.

Connection tests are blocked until the missing items in [`ABI_REQUIREMENTS.md`](ABI_REQUIREMENTS.md) are implemented.

## Host and CI tests

- Check formatting with the pinned development toolchain.
- Run all host unit tests and Clippy with all features.
- Build the core and Embassy adapter for `thumbv8m.main-none-eabihf`.
- Build the crate with the declared minimum Rust version, Rust `1.85`.
- Compile the pinned Nordic headers and run every packed size and offset assertion.
- Reject an SPI latency above eight words and an address mask above 24 bits.
- Reject a TX token count that reaches the packet-data area.
- Test all four IEEE 802.11 address modes, including four-address frames.
- Test fragmented events that arrive in more than one interrupt.
- Test an event that is larger than the caller scratch buffer.
- Test a scratch-buffer change during event assembly.
- Test Embassy RX and TX wake races and TX lease ownership.

## Power and boot hardware tests

- Run 100 cold boots and 100 warm resets.
- Confirm bounded timeouts for an absent, held-reset, and non-responsive nRF7002.
- Confirm the wake transaction at 8 MHz or less.
- Confirm all four firmware images load at their expected addresses.
- Confirm both firmware boot signatures.
- Confirm that an invalid bundle hash stops the boot before any normal traffic starts.

## Queue and interrupt hardware tests

- Confirm the firmware queue map and fixed TX command base.
- Delay interrupt processing and confirm that all queued events are drained.
- Split one event across two or more interrupts and confirm exact reassembly.
- Supply a small event buffer and confirm that all fragments of the rejected event are removed.
- Exhaust command buffers and confirm a bounded error or retry path.
- Inject SPI read and write errors at each queue ownership step.
- Confirm that no RX descriptor or TX token is reused while firmware can still own it.

## Control-plane hardware tests

- Repeat scans on 2.4 GHz and 5 GHz.
- Verify scan start, result, abort, and done events.
- After connection support exists, connect and reconnect to open, WPA2-Personal, WPA3-Personal, and transition-mode access points.
- Reject invalid credentials without a deadlock.
- Confirm disconnect result and reason handling.

## Data-plane hardware tests

- Obtain an IPv4 address through Embassy DHCP after the full connection flow exists.
- Run ICMP, TCP, and UDP traffic in both directions.
- Test minimum Ethernet frames, MTU-size frames, and ring saturation.
- Test To-DS, From-DS, no-DS, and four-address RX frames.
- Test MPDU, MSDU-with-MAC, and MSDU payload forms.
- Run sustained traffic for at least one hour while checking packet loss, descriptor leaks, token leaks, and memory corruption.

## Fault and recovery hardware tests

- Remove and restore the access point.
- Force an RPU reset while traffic runs.
- Delay or drop interrupt processing.
- Exhaust all host transmit and receive slots.
- Change the event scratch buffer during a fragmented event and confirm safe discard.
- Confirm that each fault has a bounded error or recovery path.
- Confirm that Embassy link state returns to down during recovery and returns to up only after the device is ready.
