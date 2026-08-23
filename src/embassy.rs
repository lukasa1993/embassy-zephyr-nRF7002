//! Allocation-free `embassy-net-driver` queue for the native nRF7002 runner.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::Context;

use embassy_net_driver::{
    Capabilities, Driver as EmbassyDriver, HardwareAddress, LinkState, RxToken as EmbassyRxToken,
    TxToken as EmbassyTxToken,
};
use embassy_sync::waitqueue::AtomicWaker;

const FREE: u8 = 0;
const READY: u8 = 1;
const CLIENT: u8 = 2;
const PRODUCER: u8 = 3;

/// Queue operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// The single RX slot is not available.
    RxBusy,
    /// The frame exceeds the static slot size.
    FrameTooLarge,
}

/// Outcome reported after one native TX attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOutcome {
    /// Firmware accepted the descriptor.
    Submitted,
    /// The hardware queue was temporarily full. The frame is retained.
    WouldBlock,
    /// The frame was rejected and is released.
    Dropped,
}

/// Static storage shared by `embassy-net` and the native hardware runner.
pub struct NetworkState<const FRAME_SIZE: usize> {
    mac: [u8; 6],
    link_up: AtomicBool,
    rx_state: AtomicU8,
    rx_len: AtomicUsize,
    rx: UnsafeCell<[u8; FRAME_SIZE]>,
    tx_state: AtomicU8,
    tx_len: AtomicUsize,
    tx: UnsafeCell<[u8; FRAME_SIZE]>,
    rx_waker: AtomicWaker,
    tx_space_waker: AtomicWaker,
    tx_ready_waker: AtomicWaker,
    link_waker: AtomicWaker,
}

// Every mutable buffer access is guarded by one atomic ownership state.
unsafe impl<const FRAME_SIZE: usize> Sync for NetworkState<FRAME_SIZE> {}

impl<const FRAME_SIZE: usize> NetworkState<FRAME_SIZE> {
    /// Creates a disconnected queue with one RX slot and one TX slot.
    pub const fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            link_up: AtomicBool::new(false),
            rx_state: AtomicU8::new(FREE),
            rx_len: AtomicUsize::new(0),
            rx: UnsafeCell::new([0; FRAME_SIZE]),
            tx_state: AtomicU8::new(FREE),
            tx_len: AtomicUsize::new(0),
            tx: UnsafeCell::new([0; FRAME_SIZE]),
            rx_waker: AtomicWaker::new(),
            tx_space_waker: AtomicWaker::new(),
            tx_ready_waker: AtomicWaker::new(),
            link_waker: AtomicWaker::new(),
        }
    }

    /// Returns a network driver handle.
    pub const fn driver(&self) -> NetworkDriver<'_, FRAME_SIZE> {
        NetworkDriver { state: self }
    }

    /// Returns the native producer/consumer handle.
    pub const fn runner(&self) -> NetworkRunner<'_, FRAME_SIZE> {
        NetworkRunner { state: self }
    }

    /// Returns the configured Ethernet address.
    pub const fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_state(&self) -> LinkState {
        if self.link_up.load(Ordering::Acquire) {
            LinkState::Up
        } else {
            LinkState::Down
        }
    }

    fn reserve_tx(&self) -> bool {
        self.tx_state
            .compare_exchange(FREE, CLIENT, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn reserve_receive(&self) -> bool {
        if self
            .rx_state
            .compare_exchange(READY, CLIENT, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if self.reserve_tx() {
            return true;
        }
        self.rx_state.store(READY, Ordering::Release);
        false
    }

    fn release_tx(&self) {
        self.tx_len.store(0, Ordering::Relaxed);
        self.tx_state.store(FREE, Ordering::Release);
        self.tx_space_waker.wake();
    }
}

/// `embassy-net-driver` view of the static queues.
pub struct NetworkDriver<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
}

impl<const FRAME_SIZE: usize> EmbassyDriver for NetworkDriver<'_, FRAME_SIZE> {
    type RxToken<'a>
        = RxToken<'a, FRAME_SIZE>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, FRAME_SIZE>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.state.link_state() == LinkState::Down {
            self.state.link_waker.register(cx.waker());
            if self.state.link_state() == LinkState::Down {
                return None;
            }
        }

        if !self.state.reserve_receive() {
            // Register before the second check. This prevents a missed wake if
            // RX becomes ready or TX space opens between the checks.
            self.state.rx_waker.register(cx.waker());
            self.state.tx_space_waker.register(cx.waker());
            if self.state.link_state() == LinkState::Down {
                self.state.link_waker.register(cx.waker());
                if self.state.link_state() == LinkState::Down {
                    return None;
                }
            }
            if !self.state.reserve_receive() {
                return None;
            }
        }

        Some((
            RxToken {
                state: self.state,
                consumed: false,
            },
            TxToken {
                state: self.state,
                consumed: false,
            },
        ))
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        if self.state.link_state() == LinkState::Down {
            self.state.link_waker.register(cx.waker());
            if self.state.link_state() == LinkState::Down {
                return None;
            }
        }
        if self.state.reserve_tx() {
            return Some(TxToken {
                state: self.state,
                consumed: false,
            });
        }
        self.state.tx_space_waker.register(cx.waker());
        if self.state.reserve_tx() {
            Some(TxToken {
                state: self.state,
                consumed: false,
            })
        } else {
            None
        }
    }

    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        let first = self.state.link_state();
        self.state.link_waker.register(cx.waker());
        let second = self.state.link_state();
        if first != second {
            cx.waker().wake_by_ref();
        }
        second
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = FRAME_SIZE;
        capabilities.max_burst_size = Some(1);
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(self.state.mac)
    }
}

/// RX token owned by `embassy-net`.
pub struct RxToken<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
    consumed: bool,
}

impl<const FRAME_SIZE: usize> EmbassyRxToken for RxToken<'_, FRAME_SIZE> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let len = self.state.rx_len.load(Ordering::Acquire).min(FRAME_SIZE);
        // The CLIENT state gives this token exclusive mutable access.
        let result = unsafe { f(&mut (&mut *self.state.rx.get())[..len]) };
        self.state.rx_len.store(0, Ordering::Relaxed);
        self.state.rx_state.store(FREE, Ordering::Release);
        self.consumed = true;
        result
    }
}

impl<const FRAME_SIZE: usize> Drop for RxToken<'_, FRAME_SIZE> {
    fn drop(&mut self) {
        if !self.consumed {
            self.state.rx_len.store(0, Ordering::Relaxed);
            self.state.rx_state.store(FREE, Ordering::Release);
            self.consumed = true;
        }
    }
}

/// TX token owned by `embassy-net`.
pub struct TxToken<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
    consumed: bool,
}

impl<const FRAME_SIZE: usize> EmbassyTxToken for TxToken<'_, FRAME_SIZE> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(
            len <= FRAME_SIZE,
            "embassy-net requested an oversized frame"
        );
        // The CLIENT state gives this token exclusive mutable access.
        let result = unsafe { f(&mut (&mut *self.state.tx.get())[..len]) };
        self.state.tx_len.store(len, Ordering::Relaxed);
        self.state.tx_state.store(READY, Ordering::Release);
        self.state.tx_ready_waker.wake();
        self.consumed = true;
        result
    }
}

impl<const FRAME_SIZE: usize> Drop for TxToken<'_, FRAME_SIZE> {
    fn drop(&mut self) {
        if !self.consumed {
            self.state.release_tx();
            self.consumed = true;
        }
    }
}

/// Native driver-side queue handle.
pub struct NetworkRunner<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
}

impl<const FRAME_SIZE: usize> NetworkRunner<'_, FRAME_SIZE> {
    /// Updates the link state visible to `embassy-net`.
    pub fn set_link_up(&self, up: bool) {
        let old = self.state.link_up.swap(up, Ordering::AcqRel);
        if old != up {
            self.state.link_waker.wake();
            if up {
                self.state.rx_waker.wake();
                self.state.tx_space_waker.wake();
            }
        }
    }

    /// Copies one hardware RX frame into the Embassy queue.
    pub fn push_rx(&self, frame: &[u8]) -> Result<(), QueueError> {
        if frame.len() > FRAME_SIZE {
            return Err(QueueError::FrameTooLarge);
        }
        self.state
            .rx_state
            .compare_exchange(FREE, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| QueueError::RxBusy)?;
        // The PRODUCER state gives this runner exclusive mutable access.
        unsafe {
            (&mut *self.state.rx.get())[..frame.len()].copy_from_slice(frame);
        }
        self.state.rx_len.store(frame.len(), Ordering::Relaxed);
        self.state.rx_state.store(READY, Ordering::Release);
        self.state.rx_waker.wake();
        Ok(())
    }

    /// Takes one frame prepared by `embassy-net`.
    pub fn take_tx(&self) -> Option<TxLease<'_, FRAME_SIZE>> {
        if self
            .state
            .tx_state
            .compare_exchange(READY, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        Some(TxLease {
            state: self.state,
            released: false,
        })
    }

    /// Registers a waker for new TX frames.
    ///
    /// Check [`NetworkRunner::take_tx`] again after registration to prevent a
    /// missed wake between an earlier check and this call.
    pub fn register_tx_waker(&self, cx: &mut Context<'_>) {
        self.state.tx_ready_waker.register(cx.waker());
    }
}

/// One immutable TX queue lease held by the native runner.
pub struct TxLease<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
    released: bool,
}

impl<const FRAME_SIZE: usize> TxLease<'_, FRAME_SIZE> {
    /// Returns the queued frame.
    pub fn as_slice(&self) -> &[u8] {
        let len = self.state.tx_len.load(Ordering::Acquire).min(FRAME_SIZE);
        // The PRODUCER state prevents any mutable writer until release.
        unsafe { &(&*self.state.tx.get())[..len] }
    }

    /// Reports the hardware result and consumes this lease.
    ///
    /// Consuming the lease prevents access to the buffer after ownership is
    /// returned to `embassy-net`.
    pub fn report(mut self, outcome: TxOutcome) {
        match outcome {
            TxOutcome::WouldBlock => {
                self.state.tx_state.store(READY, Ordering::Release);
                self.state.tx_ready_waker.wake();
            }
            TxOutcome::Submitted | TxOutcome::Dropped => self.state.release_tx(),
        }
        self.released = true;
    }
}

impl<const FRAME_SIZE: usize> Drop for TxLease<'_, FRAME_SIZE> {
    fn drop(&mut self) {
        if !self.released {
            self.state.tx_state.store(READY, Ordering::Release);
            self.state.tx_ready_waker.wake();
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_rx_queue_is_bounded() {
        let state = NetworkState::<64>::new([2, 0, 0, 0, 0, 1]);
        let runner = state.runner();
        runner.push_rx(&[1, 2, 3]).unwrap();
        assert_eq!(runner.push_rx(&[4]), Err(QueueError::RxBusy));
    }

    #[test]
    fn oversized_rx_is_rejected() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        assert_eq!(
            state.runner().push_rx(&[0; 9]),
            Err(QueueError::FrameTooLarge)
        );
    }

    #[test]
    fn reporting_tx_consumes_and_releases_the_lease() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        state.tx_len.store(1, Ordering::Relaxed);
        state.tx_state.store(READY, Ordering::Release);
        let runner = state.runner();
        let lease = runner.take_tx().unwrap();
        assert_eq!(lease.as_slice(), &[0]);
        lease.report(TxOutcome::Dropped);
        assert_eq!(state.tx_state.load(Ordering::Acquire), FREE);
    }
}
