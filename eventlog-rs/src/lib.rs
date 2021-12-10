use tdx::actor;
use tdx::tdel;

mod tdx;

pub const TEE_TDX: usize = 0x01;

#[macro_use]
extern crate log;

pub fn fetch_hashes(event_data: Vec<Vec<u8>>, tee: usize) -> Vec<Vec<u8>>{
    match tee {
        TEE_TDX => {
            // event_data[0]: "/sys/firmware/acpi/tables/TDEL"
            // event_data[1]: "/sys/firmware/acpi/tables/data/TDEL"
            let tdel = tdel::TDEL::new(event_data[0].clone());
            let mut actor = actor::TDEventLogActor::new(
                tdel.log_area_start_address().unwrap(), 
                tdel.log_area_minimum_length().unwrap() as usize,
                event_data[1].clone()
            );
            actor.rtmrs().unwrap()
        },
        _ => {
            warn!("tee type {} isn't supported", tee);
            vec![]
        }
    }
}

pub fn dump(event_data: Vec<Vec<u8>>, tee: usize) {
    match tee {
        TEE_TDX => {
            // event_data[0]: "/sys/firmware/acpi/tables/TDEL"
            // event_data[1]: "/sys/firmware/acpi/tables/data/TDEL"
            let tdel = tdel::TDEL::new(event_data[0].clone());
            tdel.dump().unwrap();

            info!("");
            info!("=> Read Event Log Data - Address: 0x{:X}(0x{:X})", 
                tdel.log_area_start_address().unwrap(), 
                tdel.log_area_minimum_length().unwrap());
            let mut actor = actor::TDEventLogActor::new(
                tdel.log_area_start_address().unwrap(), 
                tdel.log_area_minimum_length().unwrap() as usize,
                event_data[1].clone()
            );
            actor.dump_td_event_logs().unwrap();
            info!("");
            info!("=> Replay Rolling Hash - RTMR");
            actor.dump_rtmrs().unwrap()
        },
        _ => {
            warn!("tee type {} isn't supported", tee)
        }
    }
}
