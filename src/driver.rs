//! Bounded split between the Zephyr L2 endpoint and `embassy-net`.
//!
//! [`Reactor`] is the only owner of the synchronous [`L2Endpoint`]. It polls
//! that endpoint, copies one received frame into the bounded RX queue, and
//! drains a TX lease. [`NetworkDriver`] is deliberately a small value that
//! only contains an immutable reference to [`SharedDevice`]; it never touches
//! Zephyr, calls an FFI function, or owns a `&mut Platform`.
//!
//! The queue storage is fixed at [`MAX_FRAME_LEN`] bytes per slot. Put one
//! [`SharedDevice`] in a `static` (or in caller-owned static storage) and pass
//! shared references to the Embassy network task and the reactor. Metadata is
//! protected by a critical-section mutex; frame bytes are accessed only while
//! a slot is exclusively leased, so no shared `&mut` alias is manufactured.

use core::cell::{RefCell, UnsafeCell};
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Context;

use embassy_net_driver::{
    Capabilities, Driver as EmbassyDriver, HardwareAddress, LinkState, RxToken as EmbassyRxToken,
    TxToken as EmbassyTxToken,
};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_sync::waitqueue::AtomicWaker;

use super::{Error, InterfaceInfo, MAX_FRAME_LEN, Platform, PollResult, ReceiveResult};

/// Maximum number of packets held in the fixed RX queue by the default split.
pub const DEFAULT_RX_SLOTS: usize = 2;

/// Maximum number of packets held in the fixed TX queue by the default split.
pub const DEFAULT_TX_SLOTS: usize = 2;

/// Every slot is a complete Zephyr bridge frame, including the Ethernet
/// header. The split never accepts a smaller caller-provided buffer.
pub const DEFAULT_PACKET_BUFFER_SIZE: usize = MAX_FRAME_LEN;

/// Convenient device type for the nRF7002 foundation profile.
pub type DefaultSharedDevice = SharedDevice<DEFAULT_RX_SLOTS, DEFAULT_TX_SLOTS>;

/// Safe synchronous endpoint contract consumed by [`Reactor`].
///
/// The trait contains only owned Rust boundary types. It is also implemented
/// by a small host mock in this module's tests.
pub trait L2Endpoint {
    /// Returns immutable interface metadata after the endpoint has opened.
    fn interface(&self) -> Option<InterfaceInfo>;

    /// Polls one bounded link/event operation.
    fn poll(&mut self, timeout_ms: u32) -> Result<PollResult, Error>;

    /// Receives into a full-size caller-owned frame slot.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Error>;

    /// Sends one complete, validated Ethernet frame.
    fn send(&mut self, frame: &[u8]) -> Result<usize, Error>;
}

impl L2Endpoint for Platform {
    fn interface(&self) -> Option<InterfaceInfo> {
        Platform::interface(self)
    }

    fn poll(&mut self, timeout_ms: u32) -> Result<PollResult, Error> {
        Platform::poll(self, timeout_ms)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Error> {
        Platform::recv(self, buffer)
    }

    fn send(&mut self, frame: &[u8]) -> Result<usize, Error> {
        Platform::send(self, frame)
    }
}

/// Errors raised while constructing a split device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError {
    /// The underlying endpoint reported a safe Rust boundary error.
    Platform(Error),
    /// The endpoint was not opened before constructing the split.
    NotOpen,
    /// The shared device has not been configured by [`split`].
    NotConfigured,
    /// A shared device can only be paired with one endpoint for its lifetime.
    AlreadyConfigured,
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(formatter),
            Self::NotOpen => formatter.write_str("Zephyr L2 endpoint is not open"),
            Self::NotConfigured => formatter.write_str("shared Zephyr L2 device is not configured"),
            Self::AlreadyConfigured => {
                formatter.write_str("shared Zephyr L2 device is already configured")
            }
        }
    }
}

impl From<Error> for DriverError {
    fn from(error: Error) -> Self {
        Self::Platform(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Ready,
    InUse,
}

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct AlignedFrame([u8; MAX_FRAME_LEN]);

impl AlignedFrame {
    const fn new() -> Self {
        Self([0; MAX_FRAME_LEN])
    }
}

#[derive(Clone, Copy)]
struct SlotMeta {
    len: usize,
    state: SlotState,
    order: u32,
    epoch: u32,
}

impl SlotMeta {
    const fn new() -> Self {
        Self {
            len: 0,
            state: SlotState::Free,
            order: 0,
            epoch: 0,
        }
    }
}

struct Inner<const RX: usize, const TX: usize> {
    rx: [SlotMeta; RX],
    tx: [SlotMeta; TX],
    rx_occupied: usize,
    rx_ready: usize,
    tx_occupied: usize,
    tx_ready: usize,
    next_rx_order: u32,
    next_tx_order: u32,
    epoch: u32,
    link: LinkState,
    interface: Option<InterfaceInfo>,
}

impl<const RX: usize, const TX: usize> Inner<RX, TX> {
    const fn new() -> Self {
        Self {
            rx: [SlotMeta::new(); RX],
            tx: [SlotMeta::new(); TX],
            rx_occupied: 0,
            rx_ready: 0,
            tx_occupied: 0,
            tx_ready: 0,
            next_rx_order: 0,
            next_tx_order: 0,
            epoch: 0,
            link: LinkState::Down,
            interface: None,
        }
    }

    fn first_rx_free(&self) -> Option<usize> {
        self.rx
            .iter()
            .position(|slot| slot.state == SlotState::Free)
    }

    fn oldest_rx_ready(&self) -> Option<usize> {
        oldest_ready(&self.rx)
    }

    fn first_tx_free(&self) -> Option<usize> {
        self.tx
            .iter()
            .position(|slot| slot.state == SlotState::Free)
    }

    fn oldest_tx_ready(&self) -> Option<usize> {
        oldest_ready(&self.tx)
    }
}

fn oldest_ready(slots: &[SlotMeta]) -> Option<usize> {
    let mut oldest = None;
    for (index, slot) in slots.iter().enumerate() {
        if slot.state != SlotState::Ready {
            continue;
        }
        match oldest {
            None => oldest = Some(index),
            Some(current) if order_is_older(slot.order, slots[current].order) => {
                oldest = Some(index)
            }
            Some(_) => {}
        }
    }
    oldest
}

#[inline]
fn order_is_older(candidate: u32, current: u32) -> bool {
    candidate.wrapping_sub(current) & (1 << 31) != 0
}

/// Why an RX frame could not be accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxError {
    /// The frame is shorter than a complete Ethernet header.
    TooShort { len: usize },
    /// The frame exceeds the fixed slot size.
    TooLarge { len: usize },
    /// All configured RX slots are occupied.
    Full,
    /// The slot was reserved before a link epoch reset.
    StaleEpoch,
}

/// Result reported by a transport after attempting to send a leased frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxSubmitResult {
    /// The transport accepted the frame and the lease may be released.
    Accepted,
    /// The transport is busy; keep the lease for a later retry.
    WouldBlock,
    /// The link epoch changed; discard the stale frame.
    Stale,
}

/// A fixed-capacity, shareable RX/TX queue.
///
/// The value is intended to live in `static` storage. Its arrays are internal
/// and always use [`MAX_FRAME_LEN`] bytes per slot, so a caller cannot
/// accidentally configure an undersized frame buffer. Metadata is protected
/// by a critical-section mutex. Frame storage is touched only through a
/// reservation/token that owns its slot; link resets retire in-flight slots
/// without reusing their bytes until the owner drops them.
pub struct SharedDevice<const RX: usize, const TX: usize> {
    state: Mutex<CriticalSectionRawMutex, RefCell<Inner<RX, TX>>>,
    rx_bytes: UnsafeCell<[AlignedFrame; RX]>,
    tx_bytes: UnsafeCell<[AlignedFrame; TX]>,
    rx_full_drops: AtomicU32,
    rx_too_short_drops: AtomicU32,
    rx_too_large_drops: AtomicU32,
    rx_stale_drops: AtomicU32,
    rx_waker: AtomicWaker,
    tx_space_waker: AtomicWaker,
    tx_ready_waker: AtomicWaker,
    link_waker: AtomicWaker,
}

// SAFETY: queue metadata is accessed only while holding `state`; frame bytes
// are accessed through an owned slot token/reservation, and reset never
// recycles an InUse slot. Shared immutable references therefore cannot create
// two mutable aliases to a frame slot.
unsafe impl<const RX: usize, const TX: usize> Sync for SharedDevice<RX, TX> {}

// SAFETY: the same slot ownership invariant makes moving an unshared device
// between execution contexts safe.
unsafe impl<const RX: usize, const TX: usize> Send for SharedDevice<RX, TX> {}

impl<const RX: usize, const TX: usize> SharedDevice<RX, TX> {
    /// Creates an empty device. Call [`split`] before constructing a driver.
    pub const fn new() -> Self {
        assert!(RX > 0, "a shared device needs at least one RX slot");
        assert!(TX > 0, "a shared device needs at least one TX slot");
        Self {
            state: Mutex::new(RefCell::new(Inner::new())),
            rx_bytes: UnsafeCell::new([AlignedFrame::new(); RX]),
            tx_bytes: UnsafeCell::new([AlignedFrame::new(); TX]),
            rx_full_drops: AtomicU32::new(0),
            rx_too_short_drops: AtomicU32::new(0),
            rx_too_large_drops: AtomicU32::new(0),
            rx_stale_drops: AtomicU32::new(0),
            rx_waker: AtomicWaker::new(),
            tx_space_waker: AtomicWaker::new(),
            tx_ready_waker: AtomicWaker::new(),
            link_waker: AtomicWaker::new(),
        }
    }

    /// Returns the interface configured by [`split`].
    pub fn interface(&self) -> Option<InterfaceInfo> {
        self.with_inner(|inner| inner.interface)
    }

    /// Returns the current link state without registering a waker.
    pub fn current_link_state(&self) -> LinkState {
        self.with_inner(|inner| inner.link)
    }

    /// Returns the wrapping queue epoch.
    pub fn link_epoch(&self) -> u32 {
        self.with_inner(|inner| inner.epoch)
    }

    /// Number of complete RX frames ready for `embassy-net`.
    pub fn rx_len(&self) -> usize {
        self.with_inner(|inner| inner.rx_ready)
    }

    /// Number of complete TX frames waiting for the reactor.
    pub fn tx_len(&self) -> usize {
        self.with_inner(|inner| inner.tx_ready)
    }

    /// Number of free TX slots.
    pub fn tx_space(&self) -> usize {
        self.with_inner(|inner| TX - inner.tx_occupied)
    }

    /// Number of frames dropped because RX slots were full.
    pub fn rx_full_drops(&self) -> u32 {
        self.rx_full_drops.load(Ordering::Relaxed)
    }

    /// Number of frames rejected for being shorter than an Ethernet header.
    pub fn rx_too_short_drops(&self) -> u32 {
        self.rx_too_short_drops.load(Ordering::Relaxed)
    }

    /// Number of frames rejected for exceeding [`MAX_FRAME_LEN`].
    pub fn rx_too_large_drops(&self) -> u32 {
        self.rx_too_large_drops.load(Ordering::Relaxed)
    }

    /// Number of RX reservations invalidated by a link reset.
    pub fn rx_stale_drops(&self) -> u32 {
        self.rx_stale_drops.load(Ordering::Relaxed)
    }

    fn configure(&self, interface: InterfaceInfo) -> Result<(), DriverError> {
        self.with_inner(|inner| {
            if inner.interface.is_some() {
                return Err(DriverError::AlreadyConfigured);
            }
            inner.interface = Some(interface);
            inner.link = if interface.status().is_connected() {
                LinkState::Up
            } else {
                LinkState::Down
            };
            Ok(())
        })
    }

    /// Updates the link state. A transition away from `Up` flushes queued
    /// frames and advances the epoch. `force_reset` is used for an explicit
    /// disconnect event even when the visible state was already down.
    fn update_link(&self, state: LinkState, force_reset: bool) -> bool {
        let old = self.current_link_state();
        if state == LinkState::Down {
            if old != LinkState::Down || force_reset {
                self.reset_link(LinkState::Down);
                return old != LinkState::Down;
            }
            return false;
        }

        if old != state {
            self.with_inner(|inner| inner.link = state);
            self.link_waker.wake();
            self.tx_space_waker.wake();
            self.rx_waker.wake();
            true
        } else {
            false
        }
    }

    /// Flushes queued frames, advances the epoch, and updates the link.
    /// In-flight tokens/leases remain occupied until they are released, so a
    /// reset can never overwrite bytes still borrowed by their owner.
    pub fn reset_link(&self, state: LinkState) -> u32 {
        let epoch = self.with_inner(|inner| {
            inner.epoch = inner.epoch.wrapping_add(1);
            for slot in &mut inner.rx {
                if slot.state == SlotState::Ready {
                    slot.state = SlotState::Free;
                    slot.len = 0;
                    inner.rx_occupied -= 1;
                    inner.rx_ready -= 1;
                }
            }
            for slot in &mut inner.tx {
                if slot.state == SlotState::Ready {
                    slot.state = SlotState::Free;
                    slot.len = 0;
                    inner.tx_occupied -= 1;
                    inner.tx_ready -= 1;
                }
            }
            inner.link = state;
            inner.epoch
        });
        self.rx_waker.wake();
        self.tx_space_waker.wake();
        self.tx_ready_waker.wake();
        self.link_waker.wake();
        epoch
    }

    /// Copies a complete frame into the bounded RX queue.
    pub fn push_rx(&self, frame: &[u8]) -> Result<(), RxError> {
        if frame.len() < super::ETHERNET_HEADER_LEN {
            self.rx_too_short_drops.fetch_add(1, Ordering::Relaxed);
            return Err(RxError::TooShort { len: frame.len() });
        }
        if frame.len() > MAX_FRAME_LEN {
            self.rx_too_large_drops.fetch_add(1, Ordering::Relaxed);
            return Err(RxError::TooLarge { len: frame.len() });
        }
        let mut reservation = self.reserve_rx().ok_or_else(|| {
            self.rx_full_drops.fetch_add(1, Ordering::Relaxed);
            RxError::Full
        })?;
        reservation.buffer_mut()[..frame.len()].copy_from_slice(frame);
        reservation.commit(frame.len())
    }

    /// Takes the oldest queued TX frame as a retryable lease.
    pub fn take_tx(&self) -> Option<TxFrame<'_, RX, TX>> {
        let reservation = self.with_inner(|inner| {
            let index = inner.oldest_tx_ready()?;
            let slot = &mut inner.tx[index];
            let epoch = slot.epoch;
            slot.state = SlotState::InUse;
            inner.tx_ready -= 1;
            Some((index, epoch))
        });
        reservation.map(|(index, epoch)| TxFrame {
            device: self,
            index,
            epoch,
            released: false,
        })
    }

    fn reserve_rx(&self) -> Option<RxReservation<'_, RX, TX>> {
        let reservation = self.with_inner(|inner| {
            let index = inner.first_rx_free()?;
            let epoch = inner.epoch;
            let slot = &mut inner.rx[index];
            slot.state = SlotState::InUse;
            slot.epoch = epoch;
            slot.len = 0;
            inner.rx_occupied += 1;
            Some((index, epoch))
        })?;
        Some(RxReservation {
            device: self,
            index: reservation.0,
            epoch: reservation.1,
            committed: false,
        })
    }

    fn try_receive(&self) -> Option<(RxToken<'_, RX, TX>, TxToken<'_, RX, TX>)> {
        self.with_inner(|inner| {
            let rx_index = inner.oldest_rx_ready()?;
            let tx_index = inner.first_tx_free()?;
            let epoch = inner.epoch;
            inner.rx[rx_index].state = SlotState::InUse;
            inner.rx[rx_index].epoch = epoch;
            inner.rx_ready -= 1;
            inner.tx[tx_index].state = SlotState::InUse;
            inner.tx[tx_index].epoch = epoch;
            inner.tx_occupied += 1;
            Some((
                RxToken {
                    device: self,
                    index: rx_index,
                    epoch,
                    released: false,
                },
                TxToken {
                    device: self,
                    index: tx_index,
                    epoch,
                    committed: false,
                },
            ))
        })
    }

    fn try_transmit(&self) -> Option<TxToken<'_, RX, TX>> {
        self.with_inner(|inner| {
            let index = inner.first_tx_free()?;
            let epoch = inner.epoch;
            inner.tx[index].state = SlotState::InUse;
            inner.tx[index].epoch = epoch;
            inner.tx_occupied += 1;
            Some(TxToken {
                device: self,
                index,
                epoch,
                committed: false,
            })
        })
    }

    fn with_inner<R>(&self, f: impl FnOnce(&mut Inner<RX, TX>) -> R) -> R {
        self.state.lock(|cell| {
            let mut inner = cell.borrow_mut();
            f(&mut inner)
        })
    }

    fn rx_slot_ptr(&self, index: usize) -> *mut AlignedFrame {
        // SAFETY: callers only use this pointer after reserving/owning the
        // corresponding slot, and the array contains exactly RX elements.
        unsafe { self.rx_bytes.get().cast::<AlignedFrame>().add(index) }
    }

    fn tx_slot_ptr(&self, index: usize) -> *mut AlignedFrame {
        // SAFETY: callers only use this pointer after reserving/owning the
        // corresponding slot, and the array contains exactly TX elements.
        unsafe { self.tx_bytes.get().cast::<AlignedFrame>().add(index) }
    }

    fn rx_len_for(&self, index: usize, epoch: u32) -> Option<usize> {
        self.with_inner(|inner| {
            let slot = inner.rx.get(index)?;
            (slot.state == SlotState::InUse && slot.epoch == epoch && inner.epoch == epoch)
                .then_some(slot.len)
        })
    }

    fn tx_len_for(&self, index: usize, epoch: u32) -> Option<usize> {
        self.with_inner(|inner| {
            let slot = inner.tx.get(index)?;
            (slot.state == SlotState::InUse && slot.epoch == epoch && inner.epoch == epoch)
                .then_some(slot.len)
        })
    }

    fn tx_reserved(&self, index: usize, epoch: u32) -> bool {
        self.tx_len_for(index, epoch).is_some()
    }

    fn commit_rx(&self, index: usize, epoch: u32, len: usize) -> bool {
        let committed = self.with_inner(|inner| {
            let slot = &mut inner.rx[index];
            if slot.state != SlotState::InUse || slot.epoch != epoch || inner.epoch != epoch {
                if slot.state == SlotState::InUse && slot.epoch == epoch {
                    slot.state = SlotState::Free;
                    slot.len = 0;
                    inner.rx_occupied -= 1;
                }
                return false;
            }
            slot.len = len;
            slot.order = inner.next_rx_order;
            inner.next_rx_order = inner.next_rx_order.wrapping_add(1);
            slot.state = SlotState::Ready;
            inner.rx_ready += 1;
            true
        });
        if committed {
            self.rx_waker.wake();
        }
        committed
    }

    fn release_rx(&self, index: usize, epoch: u32) {
        self.with_inner(|inner| {
            let slot = &mut inner.rx[index];
            if slot.state == SlotState::InUse && slot.epoch == epoch {
                slot.state = SlotState::Free;
                slot.len = 0;
                inner.rx_occupied -= 1;
            }
        });
        // Releasing an RX token only frees a slot for the reactor's next
        // synchronous reservation. No Embassy task waits on RX-slot space;
        // `rx_waker` is reserved for newly committed RX data.
    }

    fn commit_tx(&self, index: usize, epoch: u32, len: usize) -> TxCommitOutcome {
        self.with_inner(|inner| {
            let slot = &mut inner.tx[index];
            if slot.state != SlotState::InUse || slot.epoch != epoch {
                return TxCommitOutcome::Rejected;
            }
            if inner.epoch != epoch {
                slot.state = SlotState::Free;
                slot.len = 0;
                inner.tx_occupied -= 1;
                return TxCommitOutcome::StaleRetired;
            }
            slot.len = len;
            slot.order = inner.next_tx_order;
            inner.next_tx_order = inner.next_tx_order.wrapping_add(1);
            slot.state = SlotState::Ready;
            inner.tx_ready += 1;
            TxCommitOutcome::Committed
        })
    }

    fn release_tx(&self, index: usize, epoch: u32) {
        let released = self.with_inner(|inner| {
            let slot = &mut inner.tx[index];
            if slot.state == SlotState::InUse && slot.epoch == epoch {
                slot.state = SlotState::Free;
                slot.len = 0;
                inner.tx_occupied -= 1;
                true
            } else {
                false
            }
        });
        if released {
            self.tx_space_waker.wake();
        }
    }
}

impl<const RX: usize, const TX: usize> Default for SharedDevice<RX, TX> {
    fn default() -> Self {
        Self::new()
    }
}

/// A short-lived reservation used by [`Reactor`] to receive directly into a
/// queue slot. Dropping without [`RxReservation::commit`] returns the slot.
struct RxReservation<'a, const RX: usize, const TX: usize> {
    device: &'a SharedDevice<RX, TX>,
    index: usize,
    epoch: u32,
    committed: bool,
}

impl<const RX: usize, const TX: usize> RxReservation<'_, RX, TX> {
    fn buffer_mut(&mut self) -> &mut [u8] {
        // SAFETY: this reservation owns the slot in the metadata state; link
        // reset never recycles an InUse slot while this borrow is alive.
        unsafe { &mut (*self.device.rx_slot_ptr(self.index)).0 }
    }

    fn commit(mut self, len: usize) -> Result<(), RxError> {
        if len < super::ETHERNET_HEADER_LEN {
            self.device
                .rx_too_short_drops
                .fetch_add(1, Ordering::Relaxed);
            self.device.release_rx(self.index, self.epoch);
            self.committed = true;
            return Err(RxError::TooShort { len });
        }
        if len > MAX_FRAME_LEN {
            self.device
                .rx_too_large_drops
                .fetch_add(1, Ordering::Relaxed);
            self.device.release_rx(self.index, self.epoch);
            self.committed = true;
            return Err(RxError::TooLarge { len });
        }
        if self.device.commit_rx(self.index, self.epoch, len) {
            self.committed = true;
            Ok(())
        } else {
            self.device.rx_stale_drops.fetch_add(1, Ordering::Relaxed);
            self.committed = true;
            Err(RxError::StaleEpoch)
        }
    }
}

impl<const RX: usize, const TX: usize> Drop for RxReservation<'_, RX, TX> {
    fn drop(&mut self) {
        if !self.committed {
            self.device.release_rx(self.index, self.epoch);
            self.committed = true;
        }
    }
}

/// A shareable Embassy network driver. It contains no Zephyr endpoint and no
/// mutable reference to the reactor; all operations are bounded queue leases.
pub struct NetworkDriver<'a, const RX: usize, const TX: usize> {
    device: &'a SharedDevice<RX, TX>,
}

impl<'a, const RX: usize, const TX: usize> NetworkDriver<'a, RX, TX> {
    /// Creates a queue-only driver after [`split`] configured the device.
    pub fn new(device: &'a SharedDevice<RX, TX>) -> Result<Self, DriverError> {
        if device.interface().is_none() {
            return Err(DriverError::NotConfigured);
        }
        Ok(Self { device })
    }

    /// Returns the shared queue boundary used by this driver.
    pub const fn device(&self) -> &'a SharedDevice<RX, TX> {
        self.device
    }
}

impl<const RX: usize, const TX: usize> EmbassyDriver for NetworkDriver<'_, RX, TX> {
    type RxToken<'a>
        = RxToken<'a, RX, TX>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, RX, TX>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.device.current_link_state() != LinkState::Up {
            self.device.rx_waker.register(cx.waker());
            return None;
        }
        if let Some(tokens) = self.device.try_receive() {
            return Some(tokens);
        }
        self.device.rx_waker.register(cx.waker());
        self.device.tx_space_waker.register(cx.waker());
        self.device.try_receive()
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        if self.device.current_link_state() != LinkState::Up {
            self.device.tx_space_waker.register(cx.waker());
            return None;
        }
        if let Some(token) = self.device.try_transmit() {
            return Some(token);
        }
        self.device.tx_space_waker.register(cx.waker());
        self.device.try_transmit()
    }

    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        let first = self.device.current_link_state();
        self.device.link_waker.register(cx.waker());
        let second = self.device.current_link_state();
        if first != second {
            cx.waker().wake_by_ref();
        }
        second
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = self
            .device
            .interface()
            .map(|interface| interface.mtu().frame_len())
            .unwrap_or(MAX_FRAME_LEN);
        capabilities.max_burst_size = Some(1);
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        let mac = self
            .device
            .interface()
            .map(|interface| *interface.mac().as_bytes())
            .unwrap_or([0; 6]);
        HardwareAddress::Ethernet(mac)
    }
}

/// A received frame token backed by one shared RX slot.
pub struct RxToken<'a, const RX: usize, const TX: usize> {
    device: &'a SharedDevice<RX, TX>,
    index: usize,
    epoch: u32,
    released: bool,
}

impl<const RX: usize, const TX: usize> EmbassyRxToken for RxToken<'_, RX, TX> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = if let Some(len) = self.device.rx_len_for(self.index, self.epoch) {
            // SAFETY: this token owns the InUse slot until the callback and
            // release complete; reset does not recycle it in the meantime.
            unsafe { f(&mut (&mut (*self.device.rx_slot_ptr(self.index)).0)[..len]) }
        } else {
            let mut empty = [];
            f(&mut empty)
        };
        self.device.release_rx(self.index, self.epoch);
        self.released = true;
        result
    }
}

impl<const RX: usize, const TX: usize> Drop for RxToken<'_, RX, TX> {
    fn drop(&mut self) {
        if !self.released {
            self.device.release_rx(self.index, self.epoch);
            self.released = true;
        }
    }
}

/// A transmit token backed by one shared TX slot.
pub struct TxToken<'a, const RX: usize, const TX: usize> {
    device: &'a SharedDevice<RX, TX>,
    index: usize,
    epoch: u32,
    committed: bool,
}

impl<const RX: usize, const TX: usize> EmbassyTxToken for TxToken<'_, RX, TX> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(
            len <= MAX_FRAME_LEN,
            "embassy-net requested an oversized frame"
        );
        let result = if self.device.tx_reserved(self.index, self.epoch) {
            // SAFETY: this token exclusively owns the InUse slot.
            unsafe { f(&mut (&mut (*self.device.tx_slot_ptr(self.index)).0)[..len]) }
        } else {
            let mut empty = [];
            f(&mut empty)
        };
        match self.device.commit_tx(self.index, self.epoch, len) {
            TxCommitOutcome::Committed => self.device.tx_ready_waker.wake(),
            TxCommitOutcome::StaleRetired => self.device.tx_space_waker.wake(),
            TxCommitOutcome::Rejected => {}
        }
        self.committed = true;
        result
    }
}

impl<const RX: usize, const TX: usize> Drop for TxToken<'_, RX, TX> {
    fn drop(&mut self) {
        if !self.committed {
            self.device.release_tx(self.index, self.epoch);
            self.committed = true;
        }
    }
}

/// A TX queue lease owned by [`Reactor`]. `WouldBlock` retains the lease and
/// therefore the exact same frame bytes for a later retry.
pub struct TxFrame<'a, const RX: usize, const TX: usize> {
    device: &'a SharedDevice<RX, TX>,
    index: usize,
    epoch: u32,
    released: bool,
}

impl<const RX: usize, const TX: usize> TxFrame<'_, RX, TX> {
    /// Returns the queued frame length, or zero after a reset/release.
    pub fn len(&self) -> usize {
        self.device.tx_len_for(self.index, self.epoch).unwrap_or(0)
    }

    /// Borrows the queued frame for one transport send attempt.
    fn frame(&self) -> Option<&[u8]> {
        let len = self.device.tx_len_for(self.index, self.epoch)?;
        // SAFETY: this lease owns the InUse slot and only exposes immutable
        // bytes to the synchronous endpoint call.
        Some(unsafe { &(&(*self.device.tx_slot_ptr(self.index)).0)[..len] })
    }

    /// Returns whether a link reset invalidated this lease.
    pub fn is_stale(&self) -> bool {
        self.device.tx_len_for(self.index, self.epoch).is_none()
    }

    /// Reports the transport result. `WouldBlock` retains ownership.
    pub fn report_submit(&mut self, result: TxSubmitResult) {
        if !matches!(result, TxSubmitResult::WouldBlock) {
            self.release_inner();
        }
    }

    /// Explicitly releases this lease.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.device.release_tx(self.index, self.epoch);
            self.released = true;
        }
    }
}

impl<const RX: usize, const TX: usize> Drop for TxFrame<'_, RX, TX> {
    fn drop(&mut self) {
        self.release_inner();
    }
}

enum TxCommitOutcome {
    Committed,
    StaleRetired,
    Rejected,
}

/// Result of one nonblocking [`Reactor::service_once`] pass.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServiceReport {
    /// Current Embassy link state after polling.
    pub link: LinkState,
    /// Link event observed in this pass, if any.
    pub event: Option<super::WifiEvent>,
    /// Whether a data RX frame was queued.
    pub rx_queued: bool,
    /// TX progress made by this pass.
    pub tx: TxProgress,
}

/// TX progress reported by [`Reactor::service_once`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxProgress {
    /// No TX lease was available.
    Idle,
    /// A queued frame was accepted.
    Accepted,
    /// The endpoint was busy; the lease is retained.
    WouldBlock,
    /// A stale lease was discarded after a link reset.
    DroppedStale,
}

/// The sole owner of the synchronous Zephyr endpoint.
pub struct Reactor<'a, E, const RX: usize, const TX: usize>
where
    E: L2Endpoint,
{
    endpoint: E,
    device: &'a SharedDevice<RX, TX>,
    pending_tx: Option<TxFrame<'a, RX, TX>>,
}

impl<'a, E, const RX: usize, const TX: usize> Reactor<'a, E, RX, TX>
where
    E: L2Endpoint,
{
    /// Creates a reactor after the shared device has been configured.
    pub fn new(endpoint: E, device: &'a SharedDevice<RX, TX>) -> Result<Self, DriverError> {
        let interface = endpoint.interface().ok_or(DriverError::NotOpen)?;
        device.configure(interface)?;
        Ok(Self {
            endpoint,
            device,
            pending_tx: None,
        })
    }

    /// Returns the shared queue used by this reactor and its network driver.
    pub const fn device(&self) -> &'a SharedDevice<RX, TX> {
        self.device
    }

    /// Runs one bounded, nonblocking reactor pass.
    ///
    /// The endpoint is polled once, at most one RX frame is copied, and at
    /// most one TX send is attempted. A TX `WouldBlock` keeps the lease in the
    /// reactor so a later call retries the same bytes.
    pub fn service_once(&mut self) -> Result<ServiceReport, Error> {
        let mut event = None;
        match self.endpoint.poll(0) {
            Ok(result) => {
                event = result.event();
                let down_event = matches!(event, Some(super::WifiEvent::Disconnected));
                self.device.update_link(
                    if result.status().is_connected() {
                        LinkState::Up
                    } else {
                        LinkState::Down
                    },
                    down_event,
                );
            }
            Err(Error::WouldBlock | Error::TimedOut) => {}
            Err(error) => return Err(error),
        }

        let link = self.device.current_link_state();
        let mut rx_queued = false;
        if link == LinkState::Up {
            rx_queued = self.service_rx()?;
        }
        let tx = self.service_tx(link)?;
        Ok(ServiceReport {
            link: self.device.current_link_state(),
            event,
            rx_queued,
            tx,
        })
    }

    fn service_rx(&mut self) -> Result<bool, Error> {
        let Some(mut reservation) = self.device.reserve_rx() else {
            return Ok(false);
        };
        match self.endpoint.recv(reservation.buffer_mut()) {
            Ok(ReceiveResult::Frame(len)) => match reservation.commit(len) {
                Ok(()) => Ok(true),
                Err(RxError::StaleEpoch) => Ok(false),
                Err(error) => Err(match error {
                    RxError::TooShort { .. } | RxError::TooLarge { .. } | RxError::Full => {
                        Error::Protocol
                    }
                    RxError::StaleEpoch => Error::WouldBlock,
                }),
            },
            Ok(ReceiveResult::Empty | ReceiveResult::Filtered)
            | Err(Error::WouldBlock | Error::TimedOut) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn service_tx(&mut self, link: LinkState) -> Result<TxProgress, Error> {
        if link != LinkState::Up {
            if let Some(lease) = self.pending_tx.take() {
                lease.release();
                return Ok(TxProgress::DroppedStale);
            }
            return Ok(TxProgress::Idle);
        }
        if self.pending_tx.is_none() {
            self.pending_tx = self.device.take_tx();
        }
        let Some(mut lease) = self.pending_tx.take() else {
            return Ok(TxProgress::Idle);
        };
        if lease.is_stale() {
            lease.release();
            return Ok(TxProgress::DroppedStale);
        }
        let frame = lease.frame().ok_or(Error::Fault)?;
        match self.endpoint.send(frame) {
            Ok(length) if length == frame.len() => {
                lease.report_submit(TxSubmitResult::Accepted);
                Ok(TxProgress::Accepted)
            }
            Ok(_) => {
                lease.release();
                Err(Error::Protocol)
            }
            Err(Error::WouldBlock) => {
                lease.report_submit(TxSubmitResult::WouldBlock);
                self.pending_tx = Some(lease);
                Ok(TxProgress::WouldBlock)
            }
            Err(Error::NotConnected | Error::NotReady) => {
                lease.release();
                self.device.reset_link(LinkState::Down);
                Err(Error::NotConnected)
            }
            Err(error) => {
                lease.release();
                Err(error)
            }
        }
    }
}

/// Both halves returned by [`split`]. Pass `driver` to `embassy-net` and call
/// `reactor.service_once()` from one Embassy task.
pub struct Split<'a, E, const RX: usize, const TX: usize>
where
    E: L2Endpoint,
{
    /// Queue-only Embassy network driver.
    pub driver: NetworkDriver<'a, RX, TX>,
    /// Sole endpoint owner and queue reactor.
    pub reactor: Reactor<'a, E, RX, TX>,
}

/// Configures the fixed queue from an opened endpoint and returns its two
/// ownership-safe halves.
pub fn split<'a, E, const RX: usize, const TX: usize>(
    endpoint: E,
    device: &'a SharedDevice<RX, TX>,
) -> Result<Split<'a, E, RX, TX>, DriverError>
where
    E: L2Endpoint,
{
    let reactor = Reactor::new(endpoint, device)?;
    let driver = NetworkDriver::new(device)?;
    Ok(Split { driver, reactor })
}

/// Descriptive alias for [`split`].
pub fn initialize<'a, E, const RX: usize, const TX: usize>(
    endpoint: E,
    device: &'a SharedDevice<RX, TX>,
) -> Result<Split<'a, E, RX, TX>, DriverError>
where
    E: L2Endpoint,
{
    split(endpoint, device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MacAddress, Mtu, Status};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    const RX: usize = 2;
    const TX: usize = 1;

    struct MockEndpoint {
        interface: InterfaceInfo,
        status: Status,
        rx: [u8; MAX_FRAME_LEN],
        rx_len: usize,
        tx_would_block: bool,
        tx_len: usize,
        last_tx: [u8; MAX_FRAME_LEN],
    }

    impl MockEndpoint {
        fn new() -> Self {
            Self {
                interface: InterfaceInfo {
                    mac: MacAddress::new([2, 0, 0, 0, 0, 1]).unwrap(),
                    mtu: Mtu::new(1500).unwrap(),
                    status: Status::Connected,
                },
                status: Status::Connected,
                rx: [0; MAX_FRAME_LEN],
                rx_len: 0,
                tx_would_block: false,
                tx_len: 0,
                last_tx: [0; MAX_FRAME_LEN],
            }
        }

        fn queue_rx(&mut self, frame: &[u8]) {
            self.rx[..frame.len()].copy_from_slice(frame);
            self.rx_len = frame.len();
        }
    }

    impl L2Endpoint for MockEndpoint {
        fn interface(&self) -> Option<InterfaceInfo> {
            Some(self.interface)
        }

        fn poll(&mut self, _timeout_ms: u32) -> Result<PollResult, Error> {
            Ok(PollResult {
                event: None,
                status: self.status,
            })
        }

        fn recv(&mut self, output: &mut [u8]) -> Result<ReceiveResult, Error> {
            if self.rx_len == 0 {
                return Err(Error::WouldBlock);
            }
            output[..self.rx_len].copy_from_slice(&self.rx[..self.rx_len]);
            let len = self.rx_len;
            self.rx_len = 0;
            Ok(ReceiveResult::Frame(len))
        }

        fn send(&mut self, frame: &[u8]) -> Result<usize, Error> {
            if self.tx_would_block {
                return Err(Error::WouldBlock);
            }
            self.tx_len = frame.len();
            self.last_tx[..frame.len()].copy_from_slice(frame);
            Ok(frame.len())
        }
    }

    fn data_frame(seed: u8) -> [u8; 64] {
        let mut frame = [0; 64];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = seed;
        frame
    }

    unsafe fn clone_waker(data: *const ()) -> RawWaker {
        RawWaker::new(data, &WAKER_VTABLE)
    }

    unsafe fn wake_waker(data: *const ()) {
        // SAFETY: tests pass a pointer to a live AtomicUsize counter.
        unsafe { (&*(data as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst) };
    }

    unsafe fn wake_by_ref_waker(data: *const ()) {
        // SAFETY: same pointer contract as `wake_waker`.
        unsafe { (&*(data as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst) };
    }

    unsafe fn drop_waker(_: *const ()) {}

    static WAKER_VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

    fn counting_waker(counter: &AtomicUsize) -> Waker {
        // SAFETY: the counter outlives all wakers created in each test.
        unsafe {
            Waker::from_raw(RawWaker::new(
                counter as *const AtomicUsize as *const (),
                &WAKER_VTABLE,
            ))
        }
    }

    #[test]
    fn late_rx_wake_is_rechecked_after_registration() {
        let device: SharedDevice<RX, TX> = SharedDevice::new();
        let endpoint = MockEndpoint::new();
        let mut split = split(endpoint, &device).unwrap();
        let wake_count = AtomicUsize::new(0);
        let waker = counting_waker(&wake_count);
        let mut cx = Context::from_waker(&waker);
        assert!(split.driver.receive(&mut cx).is_none());
        assert_eq!(device.push_rx(&data_frame(1)), Ok(()));
        assert!(wake_count.load(Ordering::SeqCst) > 0);
        let (rx, tx) = split.driver.receive(&mut cx).expect("late frame");
        rx.consume(|frame| assert_eq!(frame[14], 1));
        drop(tx);
    }

    #[test]
    fn reactor_tx_would_block_retains_same_lease_until_retry() {
        let device: SharedDevice<RX, TX> = SharedDevice::new();
        let mut split = split(MockEndpoint::new(), &device).unwrap();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let token = split.driver.transmit(&mut cx).unwrap();
        token.consume(64, |frame| {
            frame[..6].copy_from_slice(&[0xff; 6]);
            frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[14] = 0x5a;
        });
        split.reactor.endpoint.tx_would_block = true;
        assert_eq!(
            split.reactor.service_once().unwrap().tx,
            TxProgress::WouldBlock
        );
        assert_eq!(device.tx_len(), 0);
        assert_eq!(device.tx_space(), 0);
        split.reactor.endpoint.tx_would_block = false;
        assert_eq!(
            split.reactor.service_once().unwrap().tx,
            TxProgress::Accepted
        );
        assert_eq!(split.reactor.endpoint.tx_len, 64);
        assert_eq!(split.reactor.endpoint.last_tx[14], 0x5a);
        assert_eq!(device.tx_space(), TX);
    }

    #[test]
    fn link_reset_flushes_ready_frames_and_invalidates_inflight_lease() {
        let device: SharedDevice<RX, TX> = SharedDevice::new();
        let mut split = split(MockEndpoint::new(), &device).unwrap();
        assert_eq!(device.push_rx(&data_frame(3)), Ok(()));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let token = split.driver.transmit(&mut cx).unwrap();
        token.consume(64, |frame| frame[14] = 9);
        assert_eq!(device.tx_len(), 1);
        let lease = device.take_tx().expect("in-flight lease");
        let old_epoch = device.link_epoch();
        device.reset_link(LinkState::Down);
        assert!(device.current_link_state() == LinkState::Down);
        assert_eq!(device.rx_len(), 0);
        assert_eq!(device.tx_len(), 0);
        assert_ne!(device.link_epoch(), old_epoch);
        assert!(lease.is_stale());
        lease.release();
        assert_eq!(device.tx_space(), TX);
    }

    #[test]
    fn reactor_feeds_rx_directly_into_shared_queue() {
        let device: SharedDevice<RX, TX> = SharedDevice::new();
        let mut endpoint = MockEndpoint::new();
        endpoint.queue_rx(&data_frame(7));
        let mut split = split(endpoint, &device).unwrap();
        let report = split.reactor.service_once().unwrap();
        assert!(report.rx_queued);
        assert_eq!(device.rx_len(), 1);
    }
}
