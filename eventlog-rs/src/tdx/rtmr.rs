use crate::tdx::binaryblob;

pub const RTMR_COUNT: usize = 4;
pub const RTMR_LENGTH_BY_BYTES: usize = 48;

#[derive(Debug, Clone)]
pub struct RTMR {
    pub blob: binaryblob::BinaryBlob,
}

impl RTMR {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            blob: binaryblob::BinaryBlob::new(0, data),
        }
    }

    pub fn rtmr(&self) -> Vec<u8> {
        let (hash, _) = self.blob.get_bytes(0, self.blob.length()).unwrap();
        hash
    }
}