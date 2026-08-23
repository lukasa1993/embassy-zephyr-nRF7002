# Hardware acceptance test plan

A native driver release is accepted only after all tests below pass on an nRF5340 plus nRF7002 target.

## Power and boot

- Run 100 cold boots and 100 warm resets.
- Confirm bounded timeouts for absent, held-reset, and non-responsive nRF7002 devices.
- Confirm firmware readback or firmware-provided integrity validation.

## Control plane

- Scan repeatedly on 2.4 GHz and 5 GHz.
- Connect and reconnect to open, WPA2-Personal, WPA3-Personal, and transition-mode access points.
- Reject invalid credentials without a driver deadlock.
- Confirm disconnect reason codes and recovery.

## Data plane

- Obtain an IPv4 address through Embassy DHCP.
- Run ICMP, TCP, and UDP traffic in both directions.
- Test minimum Ethernet frames, MTU-size frames, and ring saturation.
- Run sustained traffic for at least one hour while checking packet loss, descriptor leaks, and memory corruption.

## Fault handling

- Remove and restore the access point.
- Force an RPU reset while traffic runs.
- Delay or drop interrupt processing.
- Exhaust all host transmit and receive slots.
- Confirm that each fault has a bounded error or recovery path.
