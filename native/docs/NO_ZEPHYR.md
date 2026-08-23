# Zephyr exclusion

The `native` crate has no Zephyr dependency. It does not use Zephyr C headers, kernel objects, work queues, network buffers, device-tree access, logging, synchronization, or Wi-Fi management APIs.

Embassy board code supplies asynchronous peripheral and timer operations. The Rust RPU layer supplies firmware queues and Ethernet packets.
