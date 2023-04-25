use raw_cpuid::CpuId;

const AMD_NAPLES_ROME_FAMILY: u8 = 0x17;
const NAPLES_MODEL_LOW: u8 = 0x00;
const NAPLES_MODEL_HIGH: u8 = 0x0F;
const ROME_MODEL_LOW: u8 = 0x30;
const ROME_MODEL_HIGH: u8 = 0x3F;
const AMD_MILAN_FAMILY: u8 = 0x19;
const MILAN_MODEL_LOW: u8 = 0x00;
const MILAN_MODEL_HIGH: u8 = 0x0F;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum DeviceType {
    AmdRome,
    AmdNaples,
    AmdMilan,
    Unknown,
}

pub fn get_device_type() -> DeviceType {
    let feature_info = CpuId::new()
        .get_feature_info()
        .expect("Cannot get feature information");

    let family_id = feature_info.family_id();
    let modle_id = feature_info.model_id();

    let mut device_type = DeviceType::Unknown;

    match family_id {
        AMD_NAPLES_ROME_FAMILY => {
            if (NAPLES_MODEL_LOW..=NAPLES_MODEL_HIGH).contains(&modle_id) {
                device_type = DeviceType::AmdNaples;
            } else if (ROME_MODEL_LOW..=ROME_MODEL_HIGH).contains(&modle_id) {
                device_type = DeviceType::AmdRome;
            }
        }
        AMD_MILAN_FAMILY => {
            if (MILAN_MODEL_LOW..=MILAN_MODEL_HIGH).contains(&modle_id) {
                device_type = DeviceType::AmdMilan;
            }
        }
        _ => device_type = DeviceType::Unknown,
    };

    device_type
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_device_type() {
        let device_type = get_device_type();

        assert_ne!(device_type, DeviceType::Unknown);
    }
}
