extern crate serde;

use self::serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrap_type: String,
}
