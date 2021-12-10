
use anyhow::{Result, Context};
use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Debug, Clone)]
pub struct BinaryBlob {
    _data: Vec<u8>,
    _base_address: u64,
}

impl BinaryBlob {
    pub fn new(address: u64, data: Vec<u8>) -> Self {
        Self {
            _data: data, 
            _base_address: address,
        }
    }

    pub fn length(&self) -> usize {
        self._data.len()
    }

    pub fn get_uint16(&self, pos: usize) -> Result<(u16, usize)> {
        (&self._data[pos..(pos+2)]).read_u16::<LittleEndian>()
            .context(format!("read_u16 failed"))
            .and_then(|d| {Ok((d, pos + 2))})
    }

    pub fn get_uint8(&self, pos: usize) -> Result<(u8, usize)> {
        Ok((self._data[pos], pos + 1))
    }

    pub fn get_uint32(&self, pos: usize) -> Result<(u32, usize)> {
        (&self._data[pos..(pos+4)]).read_u32::<LittleEndian>()
            .context(format!("read_u32 failed"))
            .and_then(|d| {Ok((d, pos + 4))})
    }

    pub fn get_uint64(&self, pos: usize) -> Result<(u64, usize)> {
        (&self._data[pos..(pos+8)]).read_u64::<LittleEndian>()
            .context(format!("read_u64 failed"))
            .and_then(|d| {Ok((d, pos + 8))})
    }

    pub fn get_bytes(&self, pos: usize, count: usize) -> Result<(Vec<u8>, usize)>{
        Ok((self._data[pos..pos+count].to_vec(), pos + count))
    }

    pub fn dump(&self) {
        let mut index: usize = 0;

        let mut linestr = "".to_string();

        while index < self.length() {
            if (index % 16) == 0 {
                if linestr != "" {
                    info!("{}", linestr);
                }

                // line prefix string
                linestr = format!("{:08X} ", (index / 16) * 16 + self._base_address as usize);
            }

            linestr += format!("{:02X} ", self._data[index]).as_str();

            index += 1            
        }

        info!("{}", linestr);    
    }
}