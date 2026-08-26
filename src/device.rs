//! Native RPU queue, command, event, and interrupt controller.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::MAX_STATION_MESSAGE_LEN;
use super::memory::{Processor, Rpu, RpuError};
use super::protocol::{
    HOST_MESSAGE_HEADER_LEN, HPQM_INFO_LEN, HostMessageRef, HpqmInfo, ProtocolError, ScanReason,
    ScanRequest, SystemInitConfig, encode_deauthenticate, encode_get_scan_results,
    encode_new_interface, encode_scan, encode_system_init, parse_host_message,
};
use super::protocol::{InterfaceType, MAX_CONTROL_MESSAGE_LEN, SYSTEM_INIT_LEN};

/// Firmware-published host-port queue map.
pub const RPU_MEM_HPQ_INFO: u32 = 0xb000_0024;
/// LMAC RX command-slot base pointer.
pub const RPU_MEM_RX_CMD_BASE: u32 = 0xb700_0d58;
/// Fixed UMAC TX command-slot base.
pub const RPU_MEM_TX_CMD_BASE: u32 = 0xb000_00b8;
/// Root interrupt mask register.
pub const RPU_REG_INT_FROM_RPU_CTRL: u32 = 0xa400_0400;
/// Host-to-RPU command trigger register.
pub const RPU_REG_INT_TO_MCU_CTRL: u32 = 0xa400_0480;
/// Host acknowledgement register.
pub const RPU_REG_INT_FROM_MCU_ACK: u32 = 0xa400_0488;
/// UMAC interrupt enable register.
pub const RPU_REG_INT_FROM_MCU_CTRL: u32 = 0xa400_0494;
/// Root interrupt bit used by the RPU.
pub const RPU_INTERRUPT_ROOT_BIT: u32 = 1 << 17;
/// MCU interrupt and acknowledgement bit.
pub const RPU_INTERRUPT_MCU_BIT: u32 = 1 << 31;
/// Command counter synchronization value used by Nordic's HAL.
pub const RPU_COMMAND_COUNTER_START: u32 = 0xdead;
/// Nordic's command-buffer fragment limit.
pub const DEFAULT_CONTROL_FRAGMENT_LEN: usize = 400;
/// Largest event fragment in Nordic's pinned host interface.
pub const MAX_EVENT_FRAGMENT_LEN: usize = 1000;
/// Nordic's default event-pool fragment limit.
pub const DEFAULT_EVENT_FRAGMENT_LEN: usize = MAX_EVENT_FRAGMENT_LEN;
/// Default command-buffer polls before a timeout.
pub const DEFAULT_COMMAND_WAIT_ATTEMPTS: u16 = 1000;
/// Delay between command-buffer polls.
pub const DEFAULT_COMMAND_WAIT_DELAY_MS: u32 = 1;

/// Native queue-controller failure.
#[derive(Debug)]
pub enum DeviceError<E> {
    /// The bus or RPU memory operation failed before ownership changed.
    Rpu(RpuError<E>),
    /// A packed command or event is invalid.
    Protocol(ProtocolError),
    /// Queue metadata has not been read from firmware.
    NotInitialized,
    /// Firmware returned a malformed queue map or command base.
    InvalidQueueMap,
    /// No command buffer is currently available.
    CommandQueueEmpty,
    /// A multi-fragment command needs the bounded-wait API.
    CommandNeedsWait,
    /// No command buffer became available before the bounded wait ended.
    CommandQueueTimeout,
    /// Command ownership changed and delivery can no longer be proved.
    CommandDeliveryUncertain,
    /// The RPU must be reset and queues must be initialized again.
    RecoveryRequired,
    /// A caller changed the scratch buffer during fragmented-event assembly.
    EventBufferChanged,
    /// The event is larger than caller storage.
    EventTooLarge { declared: usize, capacity: usize },
}

impl<E> From<RpuError<E>> for DeviceError<E> {
    fn from(value: RpuError<E>) -> Self {
        Self::Rpu(value)
    }
}

impl<E> From<ProtocolError> for DeviceError<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Invalid command or event fragmentation setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentLimitError;

#[derive(Clone, Copy, Debug)]
struct PendingEvent {
    declared: usize,
    copied: usize,
    resubmit: bool,
    scratch_address: usize,
    discard: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingEventRead {
    Waiting,
    Discarded,
    Complete(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NewEvent {
    address: u32,
    declared: usize,
    first_count: usize,
    resubmit: bool,
}

/// Owns the direct RPU access path and firmware-published hardware queues.
pub struct Device<B> {
    rpu: Rpu<B>,
    queues: Option<HpqmInfo>,
    rx_command_base: u32,
    tx_command_base: u32,
    command_counter: u32,
    command_fragment_len: usize,
    event_fragment_len: usize,
    pending_event: Option<PendingEvent>,
    recovery_required: bool,
}

impl<B> Device<B> {
    /// Creates a closed native device around one bus.
    pub const fn new(bus: B) -> Self {
        Self {
            rpu: Rpu::new(bus),
            queues: None,
            rx_command_base: 0,
            tx_command_base: 0,
            command_counter: RPU_COMMAND_COUNTER_START,
            command_fragment_len: DEFAULT_CONTROL_FRAGMENT_LEN,
            event_fragment_len: DEFAULT_EVENT_FRAGMENT_LEN,
            pending_event: None,
            recovery_required: false,
        }
    }

    /// Borrows the RPU memory controller.
    pub fn rpu_mut(&mut self) -> &mut Rpu<B> {
        &mut self.rpu
    }

    /// Releases the low-level bus.
    pub fn into_inner(self) -> B {
        self.rpu.into_inner()
    }

    /// Returns the firmware-published queue map after initialization.
    pub const fn queues(&self) -> Option<HpqmInfo> {
        self.queues
    }

    /// Returns the LMAC RX command-slot base.
    pub const fn rx_command_base(&self) -> Option<u32> {
        if self.rx_command_base == 0 {
            None
        } else {
            Some(self.rx_command_base)
        }
    }

    /// Returns the fixed UMAC TX command-slot base after initialization.
    pub const fn tx_command_base(&self) -> Option<u32> {
        if self.tx_command_base == 0 {
            None
        } else {
            Some(self.tx_command_base)
        }
    }

    /// Reports whether the RPU must be reset before more queue operations.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }

    /// Invalidates all queue metadata after a confirmed RPU reset.
    ///
    /// Call this after hardware reset and before firmware load. A later
    /// [`Device::initialize_queues`] call makes the device usable again.
    pub fn reset_queue_state(&mut self) {
        self.queues = None;
        self.rx_command_base = 0;
        self.tx_command_base = 0;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        self.pending_event = None;
        self.recovery_required = false;
    }

    #[cfg(test)]
    pub(crate) fn initialize_for_test(&mut self, queues: HpqmInfo, rx_command_base: u32) {
        self.queues = Some(queues);
        self.rx_command_base = rx_command_base;
        self.tx_command_base = RPU_MEM_TX_CMD_BASE;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        self.pending_event = None;
        self.recovery_required = false;
    }

    /// Sets command and event fragment limits.
    pub fn set_fragment_limits(
        &mut self,
        command_len: usize,
        event_len: usize,
    ) -> Result<(), FragmentLimitError> {
        if !(HOST_MESSAGE_HEADER_LEN..=DEFAULT_CONTROL_FRAGMENT_LEN).contains(&command_len)
            || !(HOST_MESSAGE_HEADER_LEN..=MAX_EVENT_FRAGMENT_LEN).contains(&event_len)
        {
            return Err(FragmentLimitError);
        }
        self.command_fragment_len = command_len;
        self.event_fragment_len = event_len;
        Ok(())
    }

    /// Marks a partly assembled event for discard.
    ///
    /// The next calls to [`Device::try_read_event`] remove its remaining
    /// fragments before they read a new event.
    pub fn discard_pending_event(&mut self) -> bool {
        let Some(mut pending) = self.pending_event else {
            return false;
        };
        pending.discard = true;
        pending.scratch_address = 0;
        self.pending_event = Some(pending);
        true
    }

    fn ensure_operational<E>(&self) -> Result<(), DeviceError<E>> {
        if self.recovery_required {
            Err(DeviceError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn mark_delivery_uncertain<E>(&mut self) -> DeviceError<E> {
        self.recovery_required = true;
        DeviceError::CommandDeliveryUncertain
    }
}

impl<B> Device<B>
where
    B: Bus,
{
    /// Reads the queue map and data-command bases published after firmware boot.
    pub async fn initialize_queues(&mut self) -> Result<HpqmInfo, DeviceError<B::Error>> {
        let mut bytes = [0u8; HPQM_INFO_LEN];
        self.rpu
            .read(Processor::Umac, RPU_MEM_HPQ_INFO, &mut bytes)
            .await?;
        let queues = HpqmInfo::parse(&bytes)?;
        validate_queue_map(&queues)?;

        let rx_command_base = self
            .rpu
            .read_u32(Processor::Lmac, RPU_MEM_RX_CMD_BASE)
            .await?;
        validate_rx_command_base(rx_command_base)?;

        // Nordic's pinned HAL uses RPU_MEM_TX_CMD_BASE as the command area
        // itself. It does not read a pointer from that address.
        self.queues = Some(queues);
        self.rx_command_base = rx_command_base;
        self.tx_command_base = RPU_MEM_TX_CMD_BASE;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        self.pending_event = None;
        self.recovery_required = false;
        Ok(queues)
    }

    /// Enables the root and UMAC interrupt lines.
    pub async fn enable_interrupts(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.ensure_operational()?;
        let root = self.rpu.read_register(RPU_REG_INT_FROM_RPU_CTRL).await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_RPU_CTRL, root | RPU_INTERRUPT_ROOT_BIT)
            .await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_CTRL, RPU_INTERRUPT_MCU_BIT)
            .await?;
        Ok(())
    }

    /// Disables the root and UMAC interrupt lines.
    pub async fn disable_interrupts(&mut self) -> Result<(), DeviceError<B::Error>> {
        let root = self.rpu.read_register(RPU_REG_INT_FROM_RPU_CTRL).await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_RPU_CTRL, root & !RPU_INTERRUPT_ROOT_BIT)
            .await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_CTRL, 0)
            .await?;
        Ok(())
    }

    /// Acknowledges one RPU-to-host interrupt.
    pub async fn acknowledge_interrupt(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_ACK, RPU_INTERRUPT_MCU_BIT)
            .await?;
        Ok(())
    }

    /// Sends one command that fits one firmware command buffer.
    ///
    /// Use [`Device::send_control_with_wait`] for a command that needs more
    /// than one fragment. This rule prevents a normal queue-empty result after
    /// firmware already received the first part of a command.
    pub async fn send_control(&mut self, message: &[u8]) -> Result<(), DeviceError<B::Error>> {
        validate_complete_message(message)?;
        self.ensure_operational()?;
        if message.len() > self.command_fragment_len {
            return Err(DeviceError::CommandNeedsWait);
        }
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        let address = self.take_command_buffer(queues.command_available).await?;
        self.post_control_fragment(queues, address, message).await
    }

    /// Sends a complete command with a bounded wait for each command buffer.
    ///
    /// If a timeout or bus error occurs after ownership changes, the method
    /// marks the device for recovery. Reset the RPU and initialize the queues
    /// before more commands are sent.
    pub async fn send_control_with_wait<D>(
        &mut self,
        message: &[u8],
        delay: &mut D,
        attempts: u16,
        delay_ms: u32,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        let queues = self.prepare_reliable_send(message, attempts)?;
        self.send_fragments_with_wait(message, queues, delay, attempts, delay_ms)
            .await
    }

    fn prepare_reliable_send<E>(
        &self,
        message: &[u8],
        attempts: u16,
    ) -> Result<HpqmInfo, DeviceError<E>> {
        validate_complete_message(message)?;
        self.ensure_operational()?;
        if attempts == 0 {
            return Err(DeviceError::CommandQueueTimeout);
        }
        self.queues.ok_or(DeviceError::NotInitialized)
    }

    async fn send_fragments_with_wait<D>(
        &mut self,
        message: &[u8],
        queues: HpqmInfo,
        delay: &mut D,
        attempts: u16,
        delay_ms: u32,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        let mut posted_any = false;
        for fragment in message.chunks(self.command_fragment_len) {
            let address = self
                .wait_for_command_buffer(
                    queues.command_available,
                    delay,
                    attempts,
                    delay_ms,
                    posted_any,
                )
                .await?;
            self.post_control_fragment(queues, address, fragment)
                .await?;
            posted_any = true;
        }
        Ok(())
    }

    async fn take_command_buffer(
        &mut self,
        queue: super::protocol::Hpq,
    ) -> Result<u32, DeviceError<B::Error>> {
        match self.dequeue(queue).await {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(DeviceError::CommandQueueEmpty),
            Err(_) => Err(self.mark_delivery_uncertain()),
        }
    }

    async fn wait_for_command_buffer<D>(
        &mut self,
        queue: super::protocol::Hpq,
        delay: &mut D,
        attempts: u16,
        delay_ms: u32,
        posted_any: bool,
    ) -> Result<u32, DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        for _ in 0..attempts {
            match self.dequeue(queue).await {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => delay.delay_ms(delay_ms).await,
                Err(_) => return Err(self.mark_delivery_uncertain()),
            }
        }
        Err(self.command_wait_timeout(posted_any))
    }

    fn command_wait_timeout<E>(&mut self, posted_any: bool) -> DeviceError<E> {
        if posted_any {
            self.mark_delivery_uncertain()
        } else {
            DeviceError::CommandQueueTimeout
        }
    }

    /// Sends a complete command with the default one-second queue wait.
    pub async fn send_control_reliable<D>(
        &mut self,
        message: &[u8],
        delay: &mut D,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        self.send_control_with_wait(
            message,
            delay,
            DEFAULT_COMMAND_WAIT_ATTEMPTS,
            DEFAULT_COMMAND_WAIT_DELAY_MS,
        )
        .await
    }

    async fn post_control_fragment(
        &mut self,
        queues: HpqmInfo,
        address: u32,
        fragment: &[u8],
    ) -> Result<(), DeviceError<B::Error>> {
        if self
            .rpu
            .write(Processor::Umac, address, fragment)
            .await
            .is_err()
        {
            return Err(self.mark_delivery_uncertain());
        }
        if self.enqueue(queues.command_busy, address).await.is_err() {
            return Err(self.mark_delivery_uncertain());
        }
        if self.trigger_command().await.is_err() {
            return Err(self.mark_delivery_uncertain());
        }
        Ok(())
    }

    /// Sends the packed system initialization command.
    pub async fn send_system_init(
        &mut self,
        config: &SystemInitConfig,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
        let len = encode_system_init(&mut message, config)?;
        self.send_control(&message[..len]).await
    }

    /// Creates a station interface in firmware.
    pub async fn add_station_interface(
        &mut self,
        wdev_id: u32,
        mac_address: [u8; 6],
        interface_name: &[u8],
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 128];
        let len = encode_new_interface(
            &mut message,
            wdev_id,
            InterfaceType::Station,
            mac_address,
            interface_name,
        )?;
        self.send_control(&message[..len]).await
    }

    /// Starts one firmware scan.
    ///
    /// The scan command is larger than one Nordic command buffer. Use
    /// [`Device::start_scan_reliable`] for normal operation.
    pub async fn start_scan(
        &mut self,
        wdev_id: u32,
        request: &ScanRequest<'_>,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut message, wdev_id, request)?;
        self.send_control(&message[..len]).await
    }

    /// Starts one firmware scan with bounded command-buffer waits.
    pub async fn start_scan_reliable<D>(
        &mut self,
        wdev_id: u32,
        request: &ScanRequest<'_>,
        delay: &mut D,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        let mut message = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut message, wdev_id, request)?;
        self.send_control_reliable(&message[..len], delay).await
    }

    /// Requests results after a scan-done event.
    pub async fn get_scan_results(
        &mut self,
        wdev_id: u32,
        reason: ScanReason,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 96];
        let len = encode_get_scan_results(&mut message, wdev_id, reason)?;
        self.send_control(&message[..len]).await
    }

    /// Sends a station deauthentication request.
    pub async fn deauthenticate(
        &mut self,
        wdev_id: u32,
        bssid: [u8; 6],
        reason_code: u16,
        local_state_change: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 96];
        let len = encode_deauthenticate(
            &mut message,
            wdev_id,
            bssid,
            reason_code,
            local_state_change,
        )?;
        self.send_control(&message[..len]).await
    }

    /// Reads and reassembles one queued event into caller storage.
    ///
    /// `Ok(None)` means that no complete event is available. It can also mean
    /// that a fragmented event is waiting for its next fragment. Keep the same
    /// scratch buffer unchanged until that event completes. If the buffer must
    /// change, call [`Device::discard_pending_event`] first.
    ///
    /// An oversized event is removed over this call and later calls. The first
    /// call returns [`DeviceError::EventTooLarge`]. Later calls discard the
    /// remaining fragments before they read a new event.
    pub async fn try_read_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        self.ensure_operational()?;
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        if self.pending_event.is_some() {
            return self.read_pending_or_next(queues, scratch).await;
        }
        self.read_new_event(queues, scratch).await
    }

    async fn read_pending_or_next<'a>(
        &mut self,
        queues: HpqmInfo,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        match self.continue_pending_event(queues, scratch).await? {
            PendingEventRead::Waiting => Ok(None),
            PendingEventRead::Discarded => self.read_new_event(queues, scratch).await,
            PendingEventRead::Complete(declared) => {
                Ok(Some(parse_host_message(&scratch[..declared])?))
            }
        }
    }

    async fn continue_pending_event(
        &mut self,
        queues: HpqmInfo,
        scratch: &mut [u8],
    ) -> Result<PendingEventRead, DeviceError<B::Error>> {
        let mut pending = self.pending_event.expect("pending event was checked");
        if pending_buffer_changed(&pending, scratch) {
            pending.discard = true;
            pending.scratch_address = 0;
            self.pending_event = Some(pending);
            return Err(DeviceError::EventBufferChanged);
        }
        let (pending, removed, complete) = self
            .drain_pending_fragments(queues, scratch, pending)
            .await?;
        self.acknowledge_removed_fragment(removed).await?;
        Ok(self.finish_pending_event(pending, complete))
    }

    async fn acknowledge_removed_fragment(
        &mut self,
        removed: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        if removed {
            self.acknowledge_interrupt().await?;
        }
        Ok(())
    }

    fn finish_pending_event(&mut self, pending: PendingEvent, complete: bool) -> PendingEventRead {
        if !complete {
            self.pending_event = Some(pending);
            return PendingEventRead::Waiting;
        }
        self.pending_event = None;
        if pending.discard {
            PendingEventRead::Discarded
        } else {
            PendingEventRead::Complete(pending.declared)
        }
    }

    async fn drain_pending_fragments(
        &mut self,
        queues: HpqmInfo,
        scratch: &mut [u8],
        mut pending: PendingEvent,
    ) -> Result<(PendingEvent, bool, bool), DeviceError<B::Error>> {
        let mut removed = false;
        while pending.copied < pending.declared {
            let Some(event_address) = self.dequeue(queues.event_busy).await? else {
                return Ok((pending, removed, false));
            };
            self.consume_pending_fragment(queues, scratch, &mut pending, event_address)
                .await?;
            removed = true;
        }
        Ok((pending, removed, true))
    }

    async fn consume_pending_fragment(
        &mut self,
        queues: HpqmInfo,
        scratch: &mut [u8],
        pending: &mut PendingEvent,
        event_address: u32,
    ) -> Result<(), DeviceError<B::Error>> {
        let count = core::cmp::min(self.event_fragment_len, pending.declared - pending.copied);
        if !pending.discard {
            self.rpu
                .read(
                    Processor::Umac,
                    event_address,
                    &mut scratch[pending.copied..pending.copied + count],
                )
                .await?;
        }
        self.release_event_fragment(queues, event_address, pending.resubmit)
            .await?;
        pending.copied += count;
        Ok(())
    }

    async fn read_new_event<'a>(
        &mut self,
        queues: HpqmInfo,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        let Some(event) = self.begin_new_event(queues).await? else {
            return Ok(None);
        };
        self.validate_new_event(queues, event, scratch.len())
            .await?;
        self.read_initial_event_fragment(queues, event, scratch)
            .await?;
        self.finish_new_event(event, scratch)
    }

    async fn read_initial_event_fragment(
        &mut self,
        queues: HpqmInfo,
        event: NewEvent,
        scratch: &mut [u8],
    ) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .read(
                Processor::Umac,
                event.address,
                &mut scratch[..event.first_count],
            )
            .await?;
        self.release_and_acknowledge_event(queues, event.address, event.resubmit)
            .await?;
        Ok(())
    }

    fn finish_new_event<'a>(
        &mut self,
        event: NewEvent,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        if event.first_count == event.declared {
            return Ok(Some(parse_host_message(&scratch[..event.declared])?));
        }
        self.pending_event = Some(PendingEvent {
            declared: event.declared,
            copied: event.first_count,
            resubmit: event.resubmit,
            scratch_address: scratch.as_mut_ptr() as usize,
            discard: false,
        });
        Ok(None)
    }

    async fn begin_new_event(
        &mut self,
        queues: HpqmInfo,
    ) -> Result<Option<NewEvent>, DeviceError<B::Error>> {
        let Some(address) = self.dequeue(queues.event_busy).await? else {
            return Ok(None);
        };
        let (declared, resubmit) = self.read_event_header(address).await?;
        Ok(Some(NewEvent {
            address,
            declared,
            first_count: core::cmp::min(self.event_fragment_len, declared),
            resubmit,
        }))
    }

    async fn validate_new_event(
        &mut self,
        queues: HpqmInfo,
        event: NewEvent,
        capacity: usize,
    ) -> Result<(), DeviceError<B::Error>> {
        if event.declared < HOST_MESSAGE_HEADER_LEN {
            self.release_and_acknowledge_event(queues, event.address, event.resubmit)
                .await?;
            return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
        }
        if event.declared > capacity {
            self.reject_oversized_event(queues, event).await?;
            return Err(DeviceError::EventTooLarge {
                declared: event.declared,
                capacity,
            });
        }
        Ok(())
    }

    async fn read_event_header(
        &mut self,
        event_address: u32,
    ) -> Result<(usize, bool), DeviceError<B::Error>> {
        let mut header = [0u8; HOST_MESSAGE_HEADER_LEN];
        self.rpu
            .read(Processor::Umac, event_address, &mut header)
            .await?;
        let declared = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let resubmit = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) != 0;
        Ok((declared, resubmit))
    }

    async fn release_and_acknowledge_event(
        &mut self,
        queues: HpqmInfo,
        event_address: u32,
        resubmit: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        self.release_event_fragment(queues, event_address, resubmit)
            .await?;
        self.acknowledge_interrupt().await
    }

    async fn reject_oversized_event(
        &mut self,
        queues: HpqmInfo,
        event: NewEvent,
    ) -> Result<(), DeviceError<B::Error>> {
        self.release_and_acknowledge_event(queues, event.address, event.resubmit)
            .await?;
        if event.first_count < event.declared {
            self.pending_event = Some(PendingEvent {
                declared: event.declared,
                copied: event.first_count,
                resubmit: event.resubmit,
                scratch_address: 0,
                discard: true,
            });
        }
        Ok(())
    }

    async fn release_event_fragment(
        &mut self,
        queues: HpqmInfo,
        event_address: u32,
        resubmit: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        if resubmit {
            self.enqueue(queues.event_available, event_address).await?;
        }
        Ok(())
    }

    pub(crate) async fn enqueue(
        &mut self,
        queue: super::protocol::Hpq,
        value: u32,
    ) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(queue.enqueue_address, value)
            .await?;
        Ok(())
    }

    pub(crate) async fn dequeue(
        &mut self,
        queue: super::protocol::Hpq,
    ) -> Result<Option<u32>, DeviceError<B::Error>> {
        let value = self.rpu.read_register(queue.dequeue_address).await?;
        if value == 0 {
            return Ok(None);
        }
        if value == 0xaaaa_aaaa {
            return Err(DeviceError::InvalidQueueMap);
        }
        self.rpu
            .write_register(queue.dequeue_address, value)
            .await?;
        Ok(Some(value))
    }

    pub(crate) async fn trigger_command(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(RPU_REG_INT_TO_MCU_CTRL, self.command_counter | 0x7fff_0000)
            .await?;
        self.command_counter = self.command_counter.wrapping_add(1);
        Ok(())
    }
}

fn queue_map_is_valid(queues: &HpqmInfo) -> bool {
    let all = [
        queues.event_busy,
        queues.event_available,
        queues.command_busy,
        queues.command_available,
        queues.rx_buffer_busy[0],
        queues.rx_buffer_busy[1],
        queues.rx_buffer_busy[2],
    ];
    all.into_iter().all(|queue| {
        queue.enqueue_address != 0
            && queue.dequeue_address != 0
            && queue.enqueue_address != 0xaaaa_aaaa
            && queue.dequeue_address != 0xaaaa_aaaa
            && queue.enqueue_address & 3 == 0
            && queue.dequeue_address & 3 == 0
    })
}

fn pending_buffer_changed(pending: &PendingEvent, scratch: &mut [u8]) -> bool {
    !pending.discard
        && (pending.scratch_address != scratch.as_mut_ptr() as usize
            || scratch.len() < pending.declared)
}

fn validate_queue_map<E>(queues: &HpqmInfo) -> Result<(), DeviceError<E>> {
    if queue_map_is_valid(queues) {
        Ok(())
    } else {
        Err(DeviceError::InvalidQueueMap)
    }
}

fn validate_rx_command_base<E>(address: u32) -> Result<(), DeviceError<E>> {
    if address == 0 || address == 0xaaaa_aaaa {
        Err(DeviceError::InvalidQueueMap)
    } else {
        Ok(())
    }
}

fn validate_complete_message<E>(message: &[u8]) -> Result<(), DeviceError<E>> {
    if message.len() < HOST_MESSAGE_HEADER_LEN || message.len() > MAX_STATION_MESSAGE_LEN {
        return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
    }
    let declared = u32::from_le_bytes([message[0], message[1], message[2], message[3]]) as usize;
    if declared != message.len() {
        return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    use super::super::memory::host_offset;
    use super::super::protocol::{HostMessageType, Hpq, RF_PARAMS_LEN, encode_host_message};
    use super::*;
    use crate::test_support::block_on;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestBusError {
        Read,
        Write,
    }

    #[derive(Default)]
    struct ScriptedBus {
        reads: VecDeque<Result<Vec<u8>, TestBusError>>,
        writes: Vec<(u32, Vec<u8>)>,
        fail_write_at: Option<usize>,
        write_attempts: usize,
    }

    impl ScriptedBus {
        fn with_reads(reads: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                reads: reads.into_iter().map(Ok).collect(),
                ..Self::default()
            }
        }
    }

    impl Bus for ScriptedBus {
        type Error = TestBusError;

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, _address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            match self.reads.pop_front() {
                Some(Ok(response)) => {
                    assert_eq!(response.len(), data.len());
                    data.copy_from_slice(&response);
                    Ok(())
                }
                Some(Err(error)) => Err(error),
                None => {
                    data.fill(0);
                    Ok(())
                }
            }
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            let attempt = self.write_attempts;
            self.write_attempts += 1;
            if self.fail_write_at == Some(attempt) {
                return Err(TestBusError::Write);
            }
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingDelay(usize);

    impl DelayNs for CountingDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            self.0 += 1;
        }
    }

    fn word(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn valid_queues() -> HpqmInfo {
        HpqmInfo {
            event_busy: Hpq {
                enqueue_address: 0xa400_6004,
                dequeue_address: 0xa400_6000,
            },
            event_available: Hpq {
                enqueue_address: 0xa400_6014,
                dequeue_address: 0xa400_6010,
            },
            command_busy: Hpq {
                enqueue_address: 0xa400_6024,
                dequeue_address: 0xa400_6020,
            },
            command_available: Hpq {
                enqueue_address: 0xa400_7004,
                dequeue_address: 0xa400_7000,
            },
            rx_buffer_busy: [
                Hpq {
                    enqueue_address: 0xa400_6034,
                    dequeue_address: 0xa400_6030,
                },
                Hpq {
                    enqueue_address: 0xa400_6044,
                    dequeue_address: 0xa400_6040,
                },
                Hpq {
                    enqueue_address: 0xa400_6054,
                    dequeue_address: 0xa400_6050,
                },
            ],
        }
    }

    fn queue_bytes(queues: HpqmInfo) -> Vec<u8> {
        let all = [
            queues.event_busy,
            queues.event_available,
            queues.command_busy,
            queues.command_available,
            queues.rx_buffer_busy[0],
            queues.rx_buffer_busy[1],
            queues.rx_buffer_busy[2],
        ];
        let mut bytes = Vec::with_capacity(HPQM_INFO_LEN);
        for queue in all {
            bytes.extend_from_slice(&queue.enqueue_address.to_le_bytes());
            bytes.extend_from_slice(&queue.dequeue_address.to_le_bytes());
        }
        bytes
    }

    fn test_device(bus: ScriptedBus) -> Device<ScriptedBus> {
        let mut device = Device::new(bus);
        device.initialize_for_test(valid_queues(), 0xb000_2000);
        device
    }

    fn message(payload: &[u8], resubmit: bool) -> Vec<u8> {
        let mut bytes = vec![0; HOST_MESSAGE_HEADER_LEN + payload.len()];
        let len =
            encode_host_message(&mut bytes, HostMessageType::System, resubmit, payload).unwrap();
        bytes.truncate(len);
        bytes
    }

    #[test]
    fn initializes_exact_queue_map_and_command_bases() {
        let queues = valid_queues();
        let bus = ScriptedBus::with_reads([queue_bytes(queues), word(0xb000_2000)]);
        let mut device = Device::new(bus);
        assert_eq!(block_on(device.initialize_queues()).unwrap(), queues);
        assert_eq!(device.queues(), Some(queues));
        assert_eq!(device.rx_command_base(), Some(0xb000_2000));
        assert_eq!(device.tx_command_base(), Some(RPU_MEM_TX_CMD_BASE));
        assert!(!device.recovery_required());

        for invalid_base in [0, 0xaaaa_aaaa] {
            let bus = ScriptedBus::with_reads([queue_bytes(queues), word(invalid_base)]);
            let mut device = Device::new(bus);
            assert!(matches!(
                block_on(device.initialize_queues()),
                Err(DeviceError::InvalidQueueMap)
            ));
        }

        let mut invalid = queues;
        invalid.command_busy.enqueue_address = 0;
        let bus = ScriptedBus::with_reads([queue_bytes(invalid)]);
        let mut device = Device::new(bus);
        assert!(matches!(
            block_on(device.initialize_queues()),
            Err(DeviceError::InvalidQueueMap)
        ));
    }

    #[test]
    fn interrupt_registers_are_enabled_disabled_and_acknowledged_exactly() {
        let root = 0x1234_5678;
        let bus = ScriptedBus::with_reads([word(root), word(root | RPU_INTERRUPT_ROOT_BIT)]);
        let mut device = test_device(bus);
        block_on(device.enable_interrupts()).unwrap();
        block_on(device.disable_interrupts()).unwrap();
        block_on(device.acknowledge_interrupt()).unwrap();
        let bus = device.into_inner();
        let values: Vec<u32> = bus
            .writes
            .iter()
            .filter(|(_, bytes)| bytes.len() == 4)
            .map(|(_, bytes)| u32::from_le_bytes(bytes.as_slice().try_into().unwrap()))
            .collect();
        assert!(values.contains(&(root | RPU_INTERRUPT_ROOT_BIT)));
        assert!(values.contains(&(root & !RPU_INTERRUPT_ROOT_BIT)));
        assert!(values.contains(&RPU_INTERRUPT_MCU_BIT));
        assert!(values.contains(&0));

        let mut blocked = test_device(ScriptedBus::default());
        blocked.recovery_required = true;
        assert!(matches!(
            block_on(blocked.enable_interrupts()),
            Err(DeviceError::RecoveryRequired)
        ));
    }

    #[test]
    fn single_fragment_control_distinguishes_empty_and_uncertain_queues() {
        let command_address = 0xb000_5000;
        let command = message(&[1, 2], false);
        let mut device = test_device(ScriptedBus::with_reads([word(command_address)]));
        block_on(device.send_control(&command)).unwrap();
        assert_eq!(device.command_counter, RPU_COMMAND_COUNTER_START + 1);
        assert!(!device.recovery_required());

        let mut empty = test_device(ScriptedBus::with_reads([word(0)]));
        assert!(matches!(
            block_on(empty.send_control(&command)),
            Err(DeviceError::CommandQueueEmpty)
        ));
        assert!(!empty.recovery_required());

        let mut corrupt = test_device(ScriptedBus::with_reads([word(0xaaaa_aaaa)]));
        assert!(matches!(
            block_on(corrupt.send_control(&command)),
            Err(DeviceError::CommandDeliveryUncertain)
        ));
        assert!(corrupt.recovery_required());

        let mut fragmented = test_device(ScriptedBus::default());
        fragmented
            .set_fragment_limits(HOST_MESSAGE_HEADER_LEN, DEFAULT_EVENT_FRAGMENT_LEN)
            .unwrap();
        assert!(matches!(
            block_on(fragmented.send_control(&command)),
            Err(DeviceError::CommandNeedsWait)
        ));
    }

    #[test]
    fn reliable_control_waits_fragments_and_marks_partial_timeout_uncertain() {
        let command = message(&[1, 2, 3, 4, 5, 6, 7, 8], false);
        let mut delay = CountingDelay::default();

        let mut zero_attempts = test_device(ScriptedBus::default());
        assert!(matches!(
            block_on(zero_attempts.send_control_with_wait(&command, &mut delay, 0, 7)),
            Err(DeviceError::CommandQueueTimeout)
        ));

        let mut timeout = test_device(ScriptedBus::with_reads([word(0), word(0)]));
        assert!(matches!(
            block_on(timeout.send_control_with_wait(&command, &mut delay, 2, 7)),
            Err(DeviceError::CommandQueueTimeout)
        ));
        assert_eq!(delay.0, 2);
        assert!(!timeout.recovery_required());

        let first = 0xb000_5000;
        let second = 0xb000_5100;
        let mut success = test_device(ScriptedBus::with_reads([word(first), word(second)]));
        success
            .set_fragment_limits(HOST_MESSAGE_HEADER_LEN, DEFAULT_EVENT_FRAGMENT_LEN)
            .unwrap();
        block_on(success.send_control_with_wait(&command, &mut delay, 2, 7)).unwrap();
        assert_eq!(success.command_counter, RPU_COMMAND_COUNTER_START + 2);
        assert!(!success.recovery_required());

        let mut partial = test_device(ScriptedBus::with_reads([word(first), word(0), word(0)]));
        partial
            .set_fragment_limits(HOST_MESSAGE_HEADER_LEN, DEFAULT_EVENT_FRAGMENT_LEN)
            .unwrap();
        assert!(matches!(
            block_on(partial.send_control_with_wait(&command, &mut delay, 2, 7)),
            Err(DeviceError::CommandDeliveryUncertain)
        ));
        assert!(partial.recovery_required());
    }

    #[test]
    fn control_bus_failures_after_dequeue_require_recovery() {
        let command = message(&[1, 2], false);
        let mut bus = ScriptedBus::with_reads([word(0xb000_5000)]);
        bus.fail_write_at = Some(1);
        let mut device = test_device(bus);
        assert!(matches!(
            block_on(device.send_control(&command)),
            Err(DeviceError::CommandDeliveryUncertain)
        ));
        assert!(device.recovery_required());

        let mut bus = ScriptedBus::default();
        bus.reads.push_back(Err(TestBusError::Read));
        let mut device = test_device(bus);
        assert!(matches!(
            block_on(device.send_control(&command)),
            Err(DeviceError::CommandDeliveryUncertain)
        ));
        assert!(device.recovery_required());
    }

    #[test]
    fn complete_and_missing_events_follow_the_queue_contract() {
        let event_address = 0xb000_5000;
        let event = message(&[9, 8, 7, 6], true);
        let bus = ScriptedBus::with_reads([
            word(event_address),
            event[..HOST_MESSAGE_HEADER_LEN].to_vec(),
            event.clone(),
        ]);
        let mut device = test_device(bus);
        let mut scratch = [0u8; 64];
        let received = block_on(device.try_read_event(&mut scratch))
            .unwrap()
            .unwrap();
        assert_eq!(received.payload, &[9, 8, 7, 6]);
        assert!(received.resubmit);
        assert!(device.pending_event.is_none());
        let bus = device.into_inner();
        let written_values: Vec<u32> = bus
            .writes
            .iter()
            .filter(|(_, bytes)| bytes.len() == 4)
            .map(|(_, bytes)| u32::from_le_bytes(bytes.as_slice().try_into().unwrap()))
            .collect();
        assert!(written_values.contains(&event_address));
        assert!(written_values.contains(&RPU_INTERRUPT_MCU_BIT));
        let release_address = host_offset(
            Processor::Umac,
            valid_queues().event_available.enqueue_address,
        )
        .unwrap();
        assert!(
            bus.writes.iter().any(
                |(address, bytes)| *address == release_address && bytes == &word(event_address)
            )
        );

        let mut empty = test_device(ScriptedBus::with_reads([word(0)]));
        assert!(
            block_on(empty.try_read_event(&mut scratch))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_and_oversized_events_are_released_and_bounded() {
        let event_address = 0xb000_5000;
        let mut short_header = [0u8; HOST_MESSAGE_HEADER_LEN];
        short_header[..4].copy_from_slice(&((HOST_MESSAGE_HEADER_LEN - 1) as u32).to_le_bytes());
        short_header[4..8].copy_from_slice(&1u32.to_le_bytes());
        let mut malformed = test_device(ScriptedBus::with_reads([
            word(event_address),
            short_header.to_vec(),
        ]));
        assert!(matches!(
            block_on(malformed.try_read_event(&mut [0; 64])),
            Err(DeviceError::Protocol(ProtocolError::InvalidLength))
        ));

        let event = message(&[1; 8], false);
        let mut oversized = test_device(ScriptedBus::with_reads([
            word(event_address),
            event[..HOST_MESSAGE_HEADER_LEN].to_vec(),
        ]));
        assert!(matches!(
            block_on(oversized.try_read_event(&mut [0; HOST_MESSAGE_HEADER_LEN + 2])),
            Err(DeviceError::EventTooLarge {
                declared,
                capacity
            }) if declared == event.len() && capacity == HOST_MESSAGE_HEADER_LEN + 2
        ));
        assert!(oversized.pending_event.is_none());
    }

    #[test]
    fn fragmented_events_resume_wait_reject_changed_buffers_and_discard() {
        let first_address = 0xb000_5000;
        let second_address = 0xb000_5100;
        let event = message(&[1, 2, 3, 4, 5, 6, 7, 8], true);
        let first_count = HOST_MESSAGE_HEADER_LEN;
        let bus = ScriptedBus::with_reads([
            word(first_address),
            event[..HOST_MESSAGE_HEADER_LEN].to_vec(),
            event[..first_count].to_vec(),
            word(0),
            word(second_address),
            event[first_count..].to_vec(),
        ]);
        let mut device = test_device(bus);
        device
            .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, first_count)
            .unwrap();
        let mut scratch = [0u8; 64];
        assert!(
            block_on(device.try_read_event(&mut scratch))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(device.try_read_event(&mut scratch))
                .unwrap()
                .is_none()
        );
        let received = block_on(device.try_read_event(&mut scratch))
            .unwrap()
            .unwrap();
        assert_eq!(received.payload, &[1, 2, 3, 4, 5, 6, 7, 8]);

        let bus = ScriptedBus::with_reads([
            word(first_address),
            event[..HOST_MESSAGE_HEADER_LEN].to_vec(),
            event[..first_count].to_vec(),
        ]);
        let mut changed = test_device(bus);
        changed
            .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, first_count)
            .unwrap();
        let mut original = [0u8; 64];
        block_on(changed.try_read_event(&mut original)).unwrap();
        let mut replacement = [0u8; 64];
        assert!(matches!(
            block_on(changed.try_read_event(&mut replacement)),
            Err(DeviceError::EventBufferChanged)
        ));
        assert!(changed.pending_event.unwrap().discard);
    }

    #[test]
    fn oversized_fragmented_event_is_discarded_before_the_next_queue_read() {
        let first_address = 0xb000_5000;
        let second_address = 0xb000_5100;
        let event = message(&[1; 20], true);
        let fragment_len = 16;
        let bus = ScriptedBus::with_reads([
            word(first_address),
            event[..HOST_MESSAGE_HEADER_LEN].to_vec(),
            word(second_address),
            word(0),
        ]);
        let mut device = test_device(bus);
        device
            .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, fragment_len)
            .unwrap();
        let mut scratch = [0u8; 20];
        let capacity = scratch.len();
        assert!(matches!(
            block_on(device.try_read_event(&mut scratch)),
            Err(DeviceError::EventTooLarge { declared, capacity: actual })
                if declared == event.len() && actual == capacity
        ));
        assert!(device.pending_event.unwrap().discard);
        assert!(
            block_on(device.try_read_event(&mut scratch))
                .unwrap()
                .is_none()
        );
        assert!(device.pending_event.is_none());
    }

    #[test]
    fn pending_fragment_acknowledgement_tracks_actual_queue_removal() {
        let mut scratch = [0u8; 32];
        let event = message(&[1, 2, 3, 4], false);
        scratch[..HOST_MESSAGE_HEADER_LEN].copy_from_slice(&event[..HOST_MESSAGE_HEADER_LEN]);

        let mut waiting = test_device(ScriptedBus::with_reads([word(0)]));
        waiting.pending_event = Some(PendingEvent {
            declared: event.len(),
            copied: HOST_MESSAGE_HEADER_LEN,
            resubmit: false,
            scratch_address: scratch.as_mut_ptr() as usize,
            discard: false,
        });
        assert!(
            block_on(waiting.try_read_event(&mut scratch))
                .unwrap()
                .is_none()
        );
        assert!(waiting.into_inner().writes.is_empty());

        let event_address = 0xb000_5100;
        let mut completing = test_device(ScriptedBus::with_reads([
            word(event_address),
            event[HOST_MESSAGE_HEADER_LEN..].to_vec(),
        ]));
        completing.pending_event = Some(PendingEvent {
            declared: event.len(),
            copied: HOST_MESSAGE_HEADER_LEN,
            resubmit: false,
            scratch_address: scratch.as_mut_ptr() as usize,
            discard: false,
        });
        assert!(
            block_on(completing.try_read_event(&mut scratch))
                .unwrap()
                .is_some()
        );
        let writes = completing.into_inner().writes;
        assert!(
            writes
                .iter()
                .any(|(_, bytes)| bytes == &word(event_address))
        );
        assert!(
            writes
                .iter()
                .any(|(_, bytes)| bytes == &word(RPU_INTERRUPT_MCU_BIT))
        );
    }

    #[test]
    fn constructor_discard_and_system_init_boundaries_are_exact() {
        let mut fresh = Device::new(ScriptedBus::default());
        assert!(!fresh.recovery_required());
        assert!(!fresh.discard_pending_event());

        let config = SystemInitConfig::new([2, 0, 0, 0, 0, 1], [0; RF_PARAMS_LEN]);
        let mut initialized = test_device(ScriptedBus::default());
        assert!(matches!(
            block_on(initialized.send_system_init(&config)),
            Err(DeviceError::CommandQueueEmpty)
        ));
    }

    #[test]
    fn queue_validation_rejects_zero_unaligned_and_sentinel_addresses() {
        let valid = valid_queues();
        assert!(queue_map_is_valid(&valid));
        let mut invalid = valid;
        invalid.event_busy.enqueue_address = 0;
        assert!(!queue_map_is_valid(&invalid));
        invalid.event_busy.enqueue_address = 5;
        assert!(!queue_map_is_valid(&invalid));
        invalid.event_busy.enqueue_address = 0xaaaa_aaaa;
        assert!(!queue_map_is_valid(&invalid));
    }

    #[test]
    fn complete_message_length_is_checked() {
        let mut bytes = [0u8; 32];
        let len = encode_host_message(&mut bytes, HostMessageType::System, false, &[1, 2]).unwrap();
        assert!(validate_complete_message::<()>(&bytes[..len]).is_ok());
        assert!(validate_complete_message::<()>(&bytes[..len - 1]).is_err());
        assert!(validate_complete_message::<()>(&[0; HOST_MESSAGE_HEADER_LEN - 1]).is_err());
        let mut too_large = vec![0; MAX_STATION_MESSAGE_LEN + 1];
        let declared = too_large.len() as u32;
        too_large[..4].copy_from_slice(&declared.to_le_bytes());
        assert!(validate_complete_message::<()>(&too_large).is_err());
    }

    #[test]
    fn fragment_limits_match_the_pinned_nordic_interface() {
        let mut device = Device::new(());
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, MAX_EVENT_FRAGMENT_LEN)
                .is_ok()
        );
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN + 1, MAX_EVENT_FRAGMENT_LEN)
                .is_err()
        );
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, MAX_EVENT_FRAGMENT_LEN + 1)
                .is_err()
        );
    }

    #[test]
    fn pending_event_can_be_changed_to_discard() {
        let mut device = Device::new(());
        device.pending_event = Some(PendingEvent {
            declared: 2000,
            copied: 1000,
            resubmit: true,
            scratch_address: 1,
            discard: false,
        });
        assert!(device.discard_pending_event());
        assert!(device.pending_event.unwrap().discard);
    }

    #[test]
    fn reset_clears_recovery_and_queue_state() {
        let mut device = Device::new(());
        device.recovery_required = true;
        device.tx_command_base = RPU_MEM_TX_CMD_BASE;
        device.reset_queue_state();
        assert!(!device.recovery_required());
        assert_eq!(device.tx_command_base(), None);
    }

    #[test]
    fn tx_command_area_is_a_fixed_address() {
        assert_eq!(RPU_MEM_TX_CMD_BASE, 0xb000_00b8);
    }
}
