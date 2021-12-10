use std::collections::HashMap;
use crate::tdx::binaryblob;
use lazy_static::lazy_static;
use anyhow::Result;

//const TPM_ALG_ERROR: u32 = 0x0;
const TPM_ALG_RSA: u32 = 0x1;
const TPM_ALG_TDES: u32 = 0x3;
const TPM_ALG_SHA256: u32 = 0xB;
const TPM_ALG_SHA384: u32 = 0xC;
const TPM_ALG_SHA512: u32 = 0xD;

lazy_static! {
    static ref TCGALGORITHMREGISTRY: HashMap<u32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(TPM_ALG_RSA, "TPM_ALG_RSA");
        map.insert(TPM_ALG_TDES, "TPM_ALG_TDES");
        map.insert(TPM_ALG_SHA256, "TPM_ALG_SHA256");
        map.insert(TPM_ALG_SHA384, "TPM_ALG_SHA384");
        map.insert(TPM_ALG_SHA512, "TPM_ALG_SHA512");
        map
    };
}

const EV_PREBOOT_CERT: u32 = 0x0;
const EV_POST_CODE: u32 = 0x1;
const EV_UNUSED: u32 = 0x2;
pub const EV_NO_ACTION: u32 = 0x3;
const EV_SEPARATOR: u32 = 0x4;
const EV_ACTION: u32 = 0x5;
const EV_EVENT_TAG: u32 = 0x6;
const EV_S_CRTM_CONTENTS: u32 = 0x7;
const EV_S_CRTM_VERSION: u32 = 0x8;
const EV_CPU_MICROCODE: u32 = 0x9;
const EV_PLATFORM_CONFIG_FLAGS: u32 = 0xa;
const EV_TABLE_OF_DEVICES: u32 = 0xb;
const EV_COMPACT_HASH: u32 = 0xc;
const EV_IPL: u32 = 0xd;
const EV_IPL_PARTITION_DATA: u32 = 0xe;
const EV_NONHOST_CODE: u32 = 0xf;
const EV_NONHOST_CONFIG: u32 = 0x10;
const EV_NONHOST_INFO: u32 = 0x11;
const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x12;

// TCG EFI Platform Specification For TPM Family 1.1 or 1.2
const EV_EFI_EVENT_BASE: u32 = 0x80000000;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = EV_EFI_EVENT_BASE + 0x1;
const EV_EFI_VARIABLE_BOOT: u32 = EV_EFI_EVENT_BASE + 0x2;
const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = EV_EFI_EVENT_BASE + 0x3;
const EV_EFI_BOOT_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x4;
const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x5;
const EV_EFI_GPT_EVENT: u32 = EV_EFI_EVENT_BASE + 0x6;
const EV_EFI_ACTION: u32 = EV_EFI_EVENT_BASE + 0x7;
const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = EV_EFI_EVENT_BASE + 0x8;
const EV_EFI_HANDOFF_TABLES: u32 = EV_EFI_EVENT_BASE + 0x9;
const EV_EFI_VARIABLE_AUTHORITY: u32 = EV_EFI_EVENT_BASE + 0xe0;

lazy_static! {
    static ref TDEVENTLOGTYPE: HashMap<u32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(EV_PREBOOT_CERT, "EV_PREBOOT_CERT");
        map.insert(EV_POST_CODE, "EV_POST_CODE");
        map.insert(EV_UNUSED, "EV_UNUSED");
        map.insert(EV_NO_ACTION, "EV_NO_ACTION");
        map.insert(EV_SEPARATOR, "EV_SEPARATOR");
        map.insert(EV_ACTION, "EV_ACTION");
        map.insert(EV_EVENT_TAG, "EV_EVENT_TAG");
        map.insert(EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS");
        map.insert(EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION");
        map.insert(EV_CPU_MICROCODE, "EV_CPU_MICROCODE");
        map.insert(EV_PLATFORM_CONFIG_FLAGS, "EV_PLATFORM_CONFIG_FLAGS");
        map.insert(EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES");
        map.insert(EV_COMPACT_HASH, "EV_COMPACT_HASH");
        map.insert(EV_IPL, "EV_IPL");
        map.insert(EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA");
        map.insert(EV_NONHOST_CODE, "EV_NONHOST_CODE");
        map.insert(EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG");
        map.insert(EV_NONHOST_INFO, "EV_NONHOST_INFO");
        map.insert(EV_OMIT_BOOT_DEVICE_EVENTS, "EV_OMIT_BOOT_DEVICE_EVENTS");
        map.insert(EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE");
        map.insert(EV_EFI_VARIABLE_DRIVER_CONFIG, "EV_EFI_VARIABLE_DRIVER_CONFIG");
        map.insert(EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT");
        map.insert(EV_EFI_BOOT_SERVICES_APPLICATION, "EV_EFI_BOOT_SERVICES_APPLICATION");
        map.insert(EV_EFI_BOOT_SERVICES_DRIVER, "EV_EFI_BOOT_SERVICES_DRIVER");
        map.insert(EV_EFI_RUNTIME_SERVICES_DRIVER, "EV_EFI_RUNTIME_SERVICES_DRIVER");
        map.insert(EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT");
        map.insert(EV_EFI_ACTION, "EV_EFI_ACTION");
        map.insert(EV_EFI_PLATFORM_FIRMWARE_BLOB, "EV_EFI_PLATFORM_FIRMWARE_BLOB");
        map.insert(EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES");
        map.insert(EV_EFI_VARIABLE_AUTHORITY, "EV_EFI_VARIABLE_AUTHORITY");
        map
    };
}

#[derive(Debug, Clone)]
pub struct TDEventLogBase {
    _address: u64,
    pub _length: usize,
    _data: Vec<u8>,
    pub _rtmr: u32,
    _etype: u32,
    _digest_count: u32,
}

impl TDEventLogBase {
    pub fn new(address: u64) -> Self {
        Self {
            _address: address,
            _length: 0,
            _data: vec![],
            _rtmr: 0,
            _etype: 0,
            _digest_count: 0,
        }
    }

    pub fn parse_header(&mut self, data: Vec<u8>) -> Result<(binaryblob::BinaryBlob, usize)> {
        let blob = binaryblob::BinaryBlob::new(0, data);

        let mut index = 0;
        let (td_register_index, pos) = blob.get_uint32(index)?;
        index = pos;

        let (etype, pos) = blob.get_uint32(index)?;
        self._etype = etype;
        index = pos;

        let (digest_count, pos) = blob.get_uint32(index)?;
        self._digest_count = digest_count;
        index = pos;

        self._rtmr = td_register_index - 1;

        Ok((blob, index))
    }

    fn dump(&self) {
        info!("RAW DATA: ----------------------------------------------");
        let blob = binaryblob::BinaryBlob::new(self._address, self._data.clone());
        blob.dump();
        info!("RAW DATA: ----------------------------------------------");
    }
}

#[derive(Debug, Clone)]
pub struct TDEventLogSpecIdHeader {
    pub _base: TDEventLogBase,
    _algorithms_number: u32,
    _digest_sizes: HashMap<u16, u16>,
}

impl TDEventLogSpecIdHeader {
    pub fn new(address: u64) -> Self {
        Self {
            _base: TDEventLogBase::new(address),
            _algorithms_number: 0,
            _digest_sizes: HashMap::new(),
        }
    }

    pub fn length(&self) -> usize {
        self._base._length
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<usize> {
        let (blob, pos) = self._base.parse_header(data.clone())?;
        let mut index = pos;

        index += 20;  // 20 zero for digest
        index += 24;  // algorithms number
        let (algorithms_number, pos) = blob.get_uint32(index)?;
        self._algorithms_number = algorithms_number;
        index = pos;

        for _ in 0..self._algorithms_number {
            let (algoid, pos) = blob.get_uint16(index)?;
            index = pos;
            let (digestsize, pos) = blob.get_uint16(index)?;
            index = pos;
            self._digest_sizes.insert(algoid, digestsize);
        }
        let (vendorsize, pos) = blob.get_uint8(index)?;
        index = pos + vendorsize as usize;
        self._base._length = index;
        for elm in data[..index].to_vec().iter() {
            self._base._data.push(elm.to_owned());
        }
        Ok(index)
    }

    pub fn dump(&self) {
        info!("RTMR              : {}", self._base._rtmr);
        info!("Type              : {} ({})", self._base._etype, TDEVENTLOGTYPE.get(&self._base._etype).unwrap().to_string());
        info!("Length            : {}", self._base._length);
        info!("Algorithms Number : {}", self._algorithms_number);
        for (algoid, size) in self._digest_sizes.iter() {
            info!("  Algorithms[0x{:X}] Size: {}", algoid, size*8);
        }
        self._base.dump();
    }
}

#[derive(Debug, Clone)]
pub struct TDEventLogEntry {
    pub _base: TDEventLogBase,
    _specid_header: TDEventLogSpecIdHeader,
    pub _digests: Vec<Vec<u8>>,
    _event_size: u32,
    _event: Vec<u8>,
    _algorithms_id: u32,
}

impl TDEventLogEntry {
    pub fn new(address: u64, specid_header: TDEventLogSpecIdHeader) -> Self {
        Self {
            _base: TDEventLogBase::new(address),
            _specid_header: specid_header,
            _digests: vec![],
            _event_size: 0,
            _event: vec![],
            _algorithms_id: 0,
        }
    }

    pub fn length(&self) -> usize {
        self._base._length
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<usize> {
        let (blob, pos) = self._base.parse_header(data.clone())?;
        let mut index = pos;

        for _ in 0..self._base._digest_count {
            let (algoid, pos) = blob.get_uint16(index)?;
            index = pos;
            self._algorithms_id = algoid as u32;

            let digest_size = self._specid_header._digest_sizes.get(&algoid).unwrap().to_owned();
            let (digest_data, pos) = blob.get_bytes(index, digest_size as usize)?;
            self._digests.push(digest_data);
            index = pos;
        }

        let (event_size, pos) = blob.get_uint32(index)?;
        self._event_size = event_size;
        index = pos;

        let (event, pos) = blob.get_bytes(index, self._event_size as usize)?;
        self._event = event;
        index = pos;

        self._base._length = index;
        for elm in data[..index].to_vec().iter() {
            self._base._data.push(elm.to_owned());
        }        
        Ok(index)
    }

    fn get_event_log_type(&self, t: &u32) -> String {
        match TDEVENTLOGTYPE.get(t) {
            Some(data) => data.to_string(),
            None => "UNKNOW".to_string(),
        }
    }

    pub fn dump(&self) {
        info!("RTMR              : {}", self._base._rtmr);
        info!("Type              : 0x{:X} ({}))", self._base._etype,
            self.get_event_log_type(&self._base._etype));
        info!("EVENT             : {}", String::from_utf8_lossy(&self._event));
        info!("Length            : {}", self._base._length);
        info!("Algorithms ID     : {} ({})", self._algorithms_id,
            TCGALGORITHMREGISTRY.get(&self._algorithms_id).unwrap().to_string());
        let mut count = 0;
        for digest in self._digests.iter() {
            info!("Digest{} :", count);
            let digest_blob = binaryblob::BinaryBlob::new(0, digest.to_owned());
            digest_blob.dump();
            count += 1;
        }
        self._base.dump();
        info!("");
    }
}