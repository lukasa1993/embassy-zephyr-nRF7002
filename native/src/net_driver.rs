use core::task::{Context, Poll};

use embassy_net_driver::{
    Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken,
};

/// Non-blocking Ethernet packet interface used by [`EmbassyNetDevice`].
///
/// A native nRF7002 runner normally owns the RPU command and data rings. It
/// implements this trait with fixed receive and transmit slots shared through
/// Embassy synchronization primitives.
pub trait PacketIo {
    /// Driver-specific packet error.
    type Error;

    /// Poll for one Ethernet frame and copy it into `destination`.
    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>>;

    /// Poll for one free transmit descriptor.
    fn poll_transmit_ready(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>>;

    /// Submit one complete Ethernet frame.
    fn transmit(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Poll the current Ethernet link state.
    fn poll_link_state(&mut self, context: &mut Context<'_>) -> Poll<bool>;

    /// Return the station MAC address.
    fn hardware_address(&self) -> [u8; 6];

    /// Receive an asynchronous packet error that the Embassy network-driver
    /// trait cannot return.
    fn on_error(&mut self, _error: Self::Error) {}

    /// Receive an invalid frame length reported by either side of the adapter.
    fn on_invalid_frame_length(&mut self, _length: usize) {}
}

/// Fixed-buffer `embassy-net-driver` adapter for an nRF7002 packet interface.
pub struct EmbassyNetDevice<I, const MTU: usize> {
    io: I,
    rx_buffer: [u8; MTU],
    tx_buffer: [u8; MTU],
    link_state: LinkState,
}

impl<I, const MTU: usize> EmbassyNetDevice<I, MTU>
where
    I: PacketIo,
{
    /// Create a link-down network device.
    #[must_use]
    pub const fn new(io: I) -> Self {
        Self {
            io,
            rx_buffer: [0; MTU],
            tx_buffer: [0; MTU],
            link_state: LinkState::Down,
        }
    }

    /// Return the packet interface.
    #[must_use]
    pub const fn io(&self) -> &I {
        &self.io
    }

    /// Mutably borrow the packet interface.
    pub fn io_mut(&mut self) -> &mut I {
        &mut self.io
    }

    /// Consume the adapter and return the packet interface.
    #[must_use]
    pub fn into_io(self) -> I {
        self.io
    }
}

/// Receive token that borrows one completed frame.
pub struct Nrf7002RxToken<'a> {
    frame: &'a mut [u8],
}

impl RxToken for Nrf7002RxToken<'_> {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        function(self.frame)
    }
}

/// Transmit token that submits the frame after the stack fills the buffer.
pub struct Nrf7002TxToken<'a, I>
where
    I: PacketIo,
{
    io: &'a mut I,
    buffer: &'a mut [u8],
}

impl<I> TxToken for Nrf7002TxToken<'_, I>
where
    I: PacketIo,
{
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if length > self.buffer.len() {
            self.io.on_invalid_frame_length(length);
            return function(&mut []);
        }

        let frame = &mut self.buffer[..length];
        let result = function(frame);
        if let Err(error) = self.io.transmit(frame) {
            self.io.on_error(error);
        }
        result
    }
}

impl<I, const MTU: usize> Driver for EmbassyNetDevice<I, MTU>
where
    I: PacketIo,
{
    type RxToken<'a>
        = Nrf7002RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = Nrf7002TxToken<'a, I>
    where
        Self: 'a;

    fn receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let Self {
            io,
            rx_buffer,
            tx_buffer,
            link_state: _,
        } = self;

        match io.poll_transmit_ready(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                io.on_error(error);
                return None;
            }
            Poll::Pending => return None,
        }

        let length = match io.poll_receive(context, rx_buffer) {
            Poll::Ready(Ok(length)) => length,
            Poll::Ready(Err(error)) => {
                io.on_error(error);
                return None;
            }
            Poll::Pending => return None,
        };

        if length > MTU {
            io.on_invalid_frame_length(length);
            return None;
        }

        Some((
            Nrf7002RxToken {
                frame: &mut rx_buffer[..length],
            },
            Nrf7002TxToken {
                io,
                buffer: tx_buffer,
            },
        ))
    }

    fn transmit(&mut self, context: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        match self.io.poll_transmit_ready(context) {
            Poll::Ready(Ok(())) => Some(Nrf7002TxToken {
                io: &mut self.io,
                buffer: &mut self.tx_buffer,
            }),
            Poll::Ready(Err(error)) => {
                self.io.on_error(error);
                None
            }
            Poll::Pending => None,
        }
    }

    fn link_state(&mut self, context: &mut Context<'_>) -> LinkState {
        if let Poll::Ready(link_up) = self.io.poll_link_state(context) {
            self.link_state = if link_up {
                LinkState::Up
            } else {
                LinkState::Down
            };
        }
        self.link_state
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.max_transmission_unit = MTU;
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(self.io.hardware_address())
    }
}

#[cfg(test)]
mod tests {
    use core::task::{Context, Poll, Wake, Waker};
    use std::{sync::Arc, vec, vec::Vec};

    use embassy_net_driver::{Driver, HardwareAddress, LinkState, RxToken, TxToken};

    use super::{EmbassyNetDevice, PacketIo};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[derive(Default)]
    struct MockIo {
        receive: Option<Vec<u8>>,
        transmitted: Vec<u8>,
        invalid_lengths: usize,
    }

    impl PacketIo for MockIo {
        type Error = ();

        fn poll_receive(
            &mut self,
            _context: &mut Context<'_>,
            destination: &mut [u8],
        ) -> Poll<Result<usize, Self::Error>> {
            let Some(frame) = self.receive.take() else {
                return Poll::Pending;
            };
            if frame.len() <= destination.len() {
                destination[..frame.len()].copy_from_slice(&frame);
            }
            Poll::Ready(Ok(frame.len()))
        }

        fn poll_transmit_ready(
            &mut self,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn transmit(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
            self.transmitted.clear();
            self.transmitted.extend_from_slice(frame);
            Ok(())
        }

        fn poll_link_state(&mut self, _context: &mut Context<'_>) -> Poll<bool> {
            Poll::Ready(true)
        }

        fn hardware_address(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 1]
        }

        fn on_invalid_frame_length(&mut self, _length: usize) {
            self.invalid_lengths += 1;
        }
    }

    fn context() -> Context<'static> {
        let waker = Waker::from(Arc::new(NoopWake));
        Context::from_waker(Box::leak(Box::new(waker)))
    }

    #[test]
    fn receive_and_immediate_reply_use_fixed_buffers() {
        let io = MockIo {
            receive: Some(vec![1, 2, 3]),
            ..MockIo::default()
        };
        let mut device = EmbassyNetDevice::<_, 1_514>::new(io);
        let mut context = context();
        let (receive, transmit) = Driver::receive(&mut device, &mut context).expect("frame");
        assert_eq!(receive.consume(|frame| frame.iter().copied().sum::<u8>()), 6);
        transmit.consume(3, |frame| frame.copy_from_slice(&[4, 5, 6]));
        assert_eq!(device.io().transmitted, [4, 5, 6]);
    }

    #[test]
    fn capabilities_and_identity_are_ethernet() {
        let mut device = EmbassyNetDevice::<_, 1_514>::new(MockIo::default());
        let mut context = context();
        assert_eq!(Driver::link_state(&mut device, &mut context), LinkState::Up);
        assert_eq!(Driver::capabilities(&device).max_transmission_unit, 1_514);
        assert_eq!(
            Driver::hardware_address(&device),
            HardwareAddress::Ethernet([2, 0, 0, 0, 0, 1])
        );
    }
}
