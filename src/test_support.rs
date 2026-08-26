use super::bus::Bus;

use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;
use std::task::Wake;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

impl Bus for () {
    type Error = ();

    async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
        Ok(0)
    }

    async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn read(&mut self, _address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
        data.fill(0);
        Ok(())
    }

    async fn write(&mut self, _address: u32, _data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}
