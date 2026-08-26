use super::bus::Bus;

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
