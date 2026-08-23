/// Ring-index operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// A ring needs at least two slots because one slot distinguishes full from empty.
    CapacityTooSmall,
    /// An index is outside the configured capacity.
    IndexOutOfRange,
    /// No producer slot is free.
    Full,
    /// No consumer slot is available.
    Empty,
}

/// Allocation-free producer and consumer cursor for an RPU descriptor ring.
///
/// One slot is always unused. This removes the ambiguous case where equal
/// producer and consumer indexes could mean either empty or full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingCursor {
    capacity: u16,
    producer: u16,
    consumer: u16,
}

impl RingCursor {
    /// Create an empty ring.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::CapacityTooSmall`] when `capacity` is less than two.
    pub const fn new(capacity: u16) -> Result<Self, RingError> {
        if capacity < 2 {
            return Err(RingError::CapacityTooSmall);
        }
        Ok(Self {
            capacity,
            producer: 0,
            consumer: 0,
        })
    }

    /// Return the number of physical slots.
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Return the current producer index.
    #[must_use]
    pub const fn producer(self) -> u16 {
        self.producer
    }

    /// Return the current consumer index.
    #[must_use]
    pub const fn consumer(self) -> u16 {
        self.consumer
    }

    /// Test whether the ring has no readable descriptors.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.producer == self.consumer
    }

    /// Test whether no producer slot is free.
    #[must_use]
    pub const fn is_full(self) -> bool {
        self.next(self.producer) == self.consumer
    }

    /// Return the number of readable descriptors.
    #[must_use]
    pub const fn used(self) -> u16 {
        if self.producer >= self.consumer {
            self.producer - self.consumer
        } else {
            self.capacity - self.consumer + self.producer
        }
    }

    /// Return the number of writable descriptors.
    #[must_use]
    pub const fn free(self) -> u16 {
        self.capacity - 1 - self.used()
    }

    /// Reserve the current producer slot and advance the producer.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::Full`] when all usable slots are reserved.
    pub fn push(&mut self) -> Result<u16, RingError> {
        if self.is_full() {
            return Err(RingError::Full);
        }
        let index = self.producer;
        self.producer = self.next(self.producer);
        Ok(index)
    }

    /// Consume the current consumer slot and advance the consumer.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::Empty`] when no descriptor is available.
    pub fn pop(&mut self) -> Result<u16, RingError> {
        if self.is_empty() {
            return Err(RingError::Empty);
        }
        let index = self.consumer;
        self.consumer = self.next(self.consumer);
        Ok(index)
    }

    /// Replace the producer index read from shared RPU memory.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::IndexOutOfRange`] for an invalid index.
    pub fn set_producer(&mut self, producer: u16) -> Result<(), RingError> {
        if producer >= self.capacity {
            return Err(RingError::IndexOutOfRange);
        }
        self.producer = producer;
        Ok(())
    }

    /// Replace the consumer index read from shared RPU memory.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::IndexOutOfRange`] for an invalid index.
    pub fn set_consumer(&mut self, consumer: u16) -> Result<(), RingError> {
        if consumer >= self.capacity {
            return Err(RingError::IndexOutOfRange);
        }
        self.consumer = consumer;
        Ok(())
    }

    const fn next(self, index: u16) -> u16 {
        if index + 1 == self.capacity {
            0
        } else {
            index + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RingCursor, RingError};

    #[test]
    fn one_slot_is_reserved() {
        let mut ring = RingCursor::new(4).expect("valid ring");
        assert_eq!(ring.free(), 3);
        assert_eq!(ring.push(), Ok(0));
        assert_eq!(ring.push(), Ok(1));
        assert_eq!(ring.push(), Ok(2));
        assert_eq!(ring.push(), Err(RingError::Full));
        assert_eq!(ring.used(), 3);
    }

    #[test]
    fn indexes_wrap_without_ambiguity() {
        let mut ring = RingCursor::new(3).expect("valid ring");
        assert_eq!(ring.push(), Ok(0));
        assert_eq!(ring.pop(), Ok(0));
        assert_eq!(ring.push(), Ok(1));
        assert_eq!(ring.pop(), Ok(1));
        assert_eq!(ring.push(), Ok(2));
        assert_eq!(ring.producer(), 0);
        assert_eq!(ring.pop(), Ok(2));
        assert!(ring.is_empty());
    }

    #[test]
    fn remote_indexes_are_checked() {
        let mut ring = RingCursor::new(8).expect("valid ring");
        assert_eq!(ring.set_producer(8), Err(RingError::IndexOutOfRange));
        assert_eq!(ring.set_consumer(7), Ok(()));
    }
}
