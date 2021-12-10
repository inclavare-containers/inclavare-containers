use anyhow::Result;
use crate::tdx::binaryblob;

pub struct TDEL {
    blob: binaryblob::BinaryBlob,
}

impl TDEL {
    fn revision(&self) -> Result<u8> {
        let (revision, _) = self.blob.get_uint8(8)?;
        Ok(revision)
    }

    fn checksum(&self) -> Result<u8> {
        let (checksum, _) = self.blob.get_uint8(9)?;
        Ok(checksum)
    }

    fn oem_id(&self) -> Result<String> {
        let (oem_id, _) = self.blob.get_bytes(10, 6)?;
        let str = std::str::from_utf8(&oem_id)?;
        Ok(str.to_string())
    }

    pub fn log_area_minimum_length(&self) -> Result<u64> {
        let (log_area_minimum_length, _) = self.blob.get_uint64(40)?;
        Ok(log_area_minimum_length)
    }

    pub fn log_area_start_address(&self) -> Result<u64> {
        let (log_area_start_address, _) = self.blob.get_uint64(48)?;
        Ok(log_area_start_address)
    }

    pub fn dump(&self) -> Result<()>{
        self.blob.dump();
        info!("Revision:     {:?}", self.revision()?);
        info!("Length:       {}", self.blob.length());
        info!("Checksum:     {:X}", self.checksum()?);
        info!("OEM ID:       {}", self.oem_id()?);
        info!("Log Lenght:   0x{:X}", self.log_area_minimum_length()?);
        info!("Log Address:  0x{:X}", self.log_area_start_address()?);
        Ok(())
    }

    pub fn new(tdel: Vec<u8>) -> Self {
        std::assert_eq!(&tdel[0..4], "TDEL".as_bytes());
        Self {
            blob: binaryblob::BinaryBlob::new(0, tdel),
        }
    }
}
