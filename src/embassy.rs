//! Allocation-free `embassy-net-driver` queue for the native nRF7002 runner.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::Context;

use embassy_net_driver::{
    Capabilities, Driver as EmbassyDriver, HardwareAddress, LinkState, RxToken as EmbassyRxToken,
    TxToken as EmbassyTxToken,
};
use embassy_sync::waitqueue::AtomicWaker;

use super::station::StationController;

const FREE: u8 = 0;
const READY: u8 = 1;
const CLIENT: u8 = 2;
const PRODUCER: u8 = 3;

/// Queue operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// The controlled port is closed.
    LinkDown,
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
    link_epoch: AtomicUsize,
    rx_state: AtomicU8,
    rx_len: AtomicUsize,
    rx_epoch: AtomicUsize,
    rx: UnsafeCell<[u8; FRAME_SIZE]>,
    tx_state: AtomicU8,
    tx_len: AtomicUsize,
    tx_epoch: AtomicUsize,
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
            link_epoch: AtomicUsize::new(0),
            rx_state: AtomicU8::new(FREE),
            rx_len: AtomicUsize::new(0),
            rx_epoch: AtomicUsize::new(0),
            rx: UnsafeCell::new([0; FRAME_SIZE]),
            tx_state: AtomicU8::new(FREE),
            tx_len: AtomicUsize::new(0),
            tx_epoch: AtomicUsize::new(0),
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

    /// Returns the native producer and consumer handle.
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

    fn active_epoch(&self) -> Option<usize> {
        for _ in 0..3 {
            let first = self.link_epoch.load(Ordering::Acquire);
            if !self.link_up.load(Ordering::Acquire) {
                return None;
            }
            let second = self.link_epoch.load(Ordering::Acquire);
            if first == second {
                return Some(first);
            }
        }
        None
    }

    fn epoch_is_active(&self, epoch: usize) -> bool {
        self.link_up.load(Ordering::Acquire)
            && self.link_epoch.load(Ordering::Acquire) == epoch
    }

    fn set_authorized_link(&self, up: bool) {
        let old = self.link_up.swap(up, Ordering::AcqRel);
        if old == up {
            return;
        }

        self.link_epoch.fetch_add(1, Ordering::AcqRel);
        self.discard_ready_rx();
        self.discard_ready_tx();
        self.link_waker.wake();
        self.rx_waker.wake();
        self.tx_space_waker.wake();
        self.tx_ready_waker.wake();
    }

    fn reserve_tx(&self, epoch: usize) -> bool {
        if !self.epoch_is_active(epoch) {
            return false;
        }
        if self
            .tx_state
            .compare_exchange(FREE, CLIENT, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.tx_epoch.store(epoch, Ordering::Release);
        if self.epoch_is_active(epoch) {
            true
        } else {
            self.release_tx();
            false
        }
    }

    fn reserve_receive(&self, epoch: usize) -> bool {
        if !self.epoch_is_active(epoch) {
            return false;
        }
        if self.rx_state.load(Ordering::Acquire) == READY
            && self.rx_epoch.load(Ordering::Acquire) != epoch
        {
            self.discard_ready_rx();
            return false;
        }
        if self
            .rx_state
            .compare_exchange(READY, CLIENT, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if self.rx_epoch.load(Ordering::Acquire) != epoch || !self.epoch_is_active(epoch) {
            self.release_rx();
            return false;
        }
        if self.reserve_tx(epoch) {
            return true;
        }
        if self.rx_epoch.load(Ordering::Acquire) == epoch && self.epoch_is_active(epoch) {
            self.rx_state.store(READY, Ordering::Release);
            self.rx_waker.wake();
        } else {
            self.release_rx();
        }
        false
    }

    fn release_rx(&self) {
        self.rx_len.store(0, Ordering::Relaxed);
        self.rx_state.store(FREE, Ordering::Release);
    }

    fn release_tx(&self) {
        self.tx_len.store(0, Ordering::Relaxed);
        self.tx_state.store(FREE, Ordering::Release);
        self.tx_space_waker.wake();
    }

    fn discard_ready_rx(&self) {
        if self
            .rx_state
            .compare_exchange(READY, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.release_rx();
        }
    }

    fn discard_ready_rx_epoch(&self, epoch: usize) {
        if self.rx_epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        if self
            .rx_state
            .compare_exchange(READY, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.release_rx();
        }
    }

    fn discard_ready_tx(&self) {
        if self
            .tx_state
            .compare_exchange(READY, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.release_tx();
        }
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
        if let Some(epoch) = self.state.active_epoch() {
            if self.state.reserve_receive(epoch) {
                return Some((
                    RxToken {
                        state: self.state,
                        epoch,
                        consumed: false,
                    },
                    TxToken {
                        state: self.state,
                        epoch,
                        consumed: false,
                    },
                ));
            }
        }

        self.state.link_waker.register(cx.waker());
        self.state.rx_waker.register(cx.waker());
        self.state.tx_space_waker.register(cx.waker());

        let epoch = self.state.active_epoch()?;
        if !self.state.reserve_receive(epoch) {
            return None;
        }
        Some((
            RxToken {
                state: self.state,
                epoch,
                consumed: false,
            },
            TxToken {
                state: self.state,
                epoch,
                consumed: false,
            },
        ))
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        if let Some(epoch) = self.state.active_epoch() {
            if self.state.reserve_tx(epoch) {
                return Some(TxToken {
                    state: self.state,
                    epoch,
                    consumed: false,
                });
            }
        }

        self.state.link_waker.register(cx.waker());
        self.state.tx_space_waker.register(cx.waker());

        let epoch = self.state.active_epoch()?;
        if !self.state.reserve_tx(epoch) {
            return None;
        }
        Some(TxToken {
            state: self.state,
            epoch,
            consumed: false,
        })
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
    epoch: usize,
    consumed: bool,
}

impl<const FRAME_SIZE: usize> EmbassyRxToken for RxToken<'_, FRAME_SIZE> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let valid = self.state.epoch_is_active(self.epoch)
            && self.state.rx_epoch.load(Ordering::Acquire) == self.epoch;
        let len = if valid {
            self.state.rx_len.load(Ordering::Acquire).min(FRAME_SIZE)
        } else {
            0
        };
        // The CLIENT state gives this token exclusive mutable access.
        let result = unsafe { f(&mut (&mut *self.state.rx.get())[..len]) };
        self.state.release_rx();
        self.consumed = true;
        result
    }
}

impl<const FRAME_SIZE: usize> Drop for RxToken<'_, FRAME_SIZE> {
    fn drop(&mut self) {
        if !self.consumed {
            self.state.release_rx();
            self.consumed = true;
        }
    }
}

/// TX token owned by `embassy-net`.
pub struct TxToken<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
    epoch: usize,
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
        if self.state.epoch_is_active(self.epoch)
            && self.state.tx_epoch.load(Ordering::Acquire) == self.epoch
        {
            self.state.tx_len.store(len, Ordering::Relaxed);
            self.state.tx_state.store(READY, Ordering::Release);
            self.state.tx_ready_waker.wake();
        } else {
            self.state.release_tx();
        }
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
    /// Synchronizes the network link with the fail-closed station port.
    ///
    /// Normal network traffic becomes visible only when the station state
    /// reports an authorized controlled port and an active carrier.
    pub fn sync_station_link(&self, station: &StationController) {
        self.state
            .set_authorized_link(station.controlled_port_open());
    }

    /// Returns the link state visible to `embassy-net`.
    pub fn link_state(&self) -> LinkState {
        self.state.link_state()
    }

    /// Copies one hardware RX frame into the Embassy queue.
    pub fn push_rx(&self, frame: &[u8]) -> Result<(), QueueError> {
        if frame.len() > FRAME_SIZE {
            return Err(QueueError::FrameTooLarge);
        }
        let epoch = self.state.active_epoch().ok_or(QueueError::LinkDown)?;
        self.state
            .rx_state
            .compare_exchange(FREE, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| QueueError::RxBusy)?;
        if !self.state.epoch_is_active(epoch) {
            self.state.release_rx();
            return Err(QueueError::LinkDown);
        }
        // The PRODUCER state gives this runner exclusive mutable access.
        unsafe {
            (&mut *self.state.rx.get())[..frame.len()].copy_from_slice(frame);
        }
        self.state.rx_epoch.store(epoch, Ordering::Relaxed);
        self.state.rx_len.store(frame.len(), Ordering::Relaxed);
        self.state.rx_state.store(READY, Ordering::Release);
        if !self.state.epoch_is_active(epoch) {
            self.state.discard_ready_rx_epoch(epoch);
            return Err(QueueError::LinkDown);
        }
        self.state.rx_waker.wake();
        Ok(())
    }

    /// Takes one frame prepared by `embassy-net`.
    pub fn take_tx(&self) -> Option<TxLease<'_, FRAME_SIZE>> {
        let epoch = self.state.active_epoch()?;
        if self.state.tx_state.load(Ordering::Acquire) == READY
            && self.state.tx_epoch.load(Ordering::Acquire) != epoch
        {
            self.state.discard_ready_tx();
            return None;
        }
        if self
            .state
            .tx_state
            .compare_exchange(READY, PRODUCER, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        if self.state.tx_epoch.load(Ordering::Acquire) != epoch
            || !self.state.epoch_is_active(epoch)
        {
            self.state.release_tx();
            return None;
        }
        Some(TxLease {
            state: self.state,
            epoch,
            released: false,
        })
    }

    /// Registers a waker for new TX frames.
    pub fn register_tx_waker(&self, cx: &mut Context<'_>) {
        self.state.tx_ready_waker.register(cx.waker());
        if let Some(epoch) = self.state.active_epoch() {
            if self.state.tx_state.load(Ordering::Acquire) == READY
                && self.state.tx_epoch.load(Ordering::Acquire) == epoch
            {
                cx.waker().wake_by_ref();
            }
        }
    }
}

/// One immutable TX queue lease held by the native runner.
pub struct TxLease<'a, const FRAME_SIZE: usize> {
    state: &'a NetworkState<FRAME_SIZE>,
    epoch: usize,
    released: bool,
}

impl<const FRAME_SIZE: usize> TxLease<'_, FRAME_SIZE> {
    /// Returns true while this lease belongs to the active connection.
    pub fn is_current(&self) -> bool {
        self.state.epoch_is_active(self.epoch)
            && self.state.tx_epoch.load(Ordering::Acquire) == self.epoch
    }

    /// Returns the queued frame, or an empty slice for a stale lease.
    pub fn as_slice(&self) -> &[u8] {
        let len = if self.is_current() {
            self.state.tx_len.load(Ordering::Acquire).min(FRAME_SIZE)
        } else {
            0
        };
        // The PRODUCER state prevents any mutable writer until release.
        unsafe { &(&*self.state.tx.get())[..len] }
    }

    /// Reports the hardware result and consumes this lease.
    ///
    /// A stale lease is always released. It cannot return an old frame to the
    /// queue after a disconnect and reconnect.
    pub fn report(mut self, outcome: TxOutcome) {
        if outcome == TxOutcome::WouldBlock && self.is_current() {
            self.state.tx_state.store(READY, Ordering::Release);
            self.state.tx_ready_waker.wake();
        } else {
            self.state.release_tx();
        }
        self.released = true;
    }
}

impl<const FRAME_SIZE: usize> Drop for TxLease<'_, FRAME_SIZE> {
    fn drop(&mut self) {
        if !self.released {
            if self.is_current() {
                self.state.tx_state.store(READY, Ordering::Release);
                self.state.tx_ready_waker.wake();
            } else {
                self.state.release_tx();
            }
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_link<const FRAME_SIZE: usize>(state: &NetworkState<FRAME_SIZE>) -> usize {
        state.set_authorized_link(true);
        state.active_epoch().unwrap()
    }

    #[test]
    fn runner_rx_queue_is_bounded() {
        let state = NetworkState::<64>::new([2, 0, 0, 0, 0, 1]);
        open_link(&state);
        let runner = state.runner();
        runner.push_rx(&[1, 2, 3]).unwrap();
        assert_eq!(runner.push_rx(&[4]), Err(QueueError::RxBusy));
    }

    #[test]
    fn closed_link_rejects_rx() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        assert_eq!(state.runner().push_rx(&[1]), Err(QueueError::LinkDown));
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
    fn link_down_purges_a_queued_tx_frame() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        let epoch = open_link(&state);
        state.tx_epoch.store(epoch, Ordering::Relaxed);
        state.tx_len.store(1, Ordering::Relaxed);
        state.tx_state.store(READY, Ordering::Release);
        state.set_authorized_link(false);
        assert_eq!(state.tx_state.load(Ordering::Acquire), FREE);
        assert_eq!(state.tx_len.load(Ordering::Acquire), 0);
    }

    #[test]
    fn stale_tx_token_cannot_publish_after_link_loss() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        let epoch = open_link(&state);
        assert!(state.reserve_tx(epoch));
        let token = TxToken {
            state: &state,
            epoch,
            consumed: false,
        };
        state.set_authorized_link(false);
        token.consume(1, |buffer| buffer[0] = 7);
        assert_eq!(state.tx_state.load(Ordering::Acquire), FREE);
        assert_eq!(state.tx_len.load(Ordering::Acquire), 0);
    }

    #[test]
    fn reporting_tx_consumes_and_releases_the_lease() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        let epoch = open_link(&state);
        state.tx_epoch.store(epoch, Ordering::Relaxed);
        state.tx_len.store(1, Ordering::Relaxed);
        state.tx_state.store(READY, Ordering::Release);
        let runner = state.runner();
        let lease = runner.take_tx().unwrap();
        assert_eq!(lease.as_slice(), &[0]);
        lease.report(TxOutcome::Dropped);
        assert_eq!(state.tx_state.load(Ordering::Acquire), FREE);
    }

    #[test]
    fn stale_lease_cannot_return_a_frame_after_reconnect() {
        let state = NetworkState::<8>::new([2, 0, 0, 0, 0, 1]);
        let epoch = open_link(&state);
        state.tx_epoch.store(epoch, Ordering::Relaxed);
        state.tx_len.store(1, Ordering::Relaxed);
        state.tx_state.store(READY, Ordering::Release);
        let runner = state.runner();
        let lease = runner.take_tx().unwrap();
        state.set_authorized_link(false);
        state.set_authorized_link(true);
        assert!(lease.as_slice().is_empty());
        lease.report(TxOutcome::WouldBlock);
        assert_eq!(state.tx_state.load(Ordering::Acquire), FREE);
    }
}
