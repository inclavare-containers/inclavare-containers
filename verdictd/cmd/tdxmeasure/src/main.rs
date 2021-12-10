use std::fs;
extern crate eventlog_rs;

#[macro_use]
extern crate log;

fn main() {
    env_logger::builder().filter(None, log::LevelFilter::Info).init();
    let mut event_data = vec![];

    let path = "/sys/firmware/acpi/tables/TDEL".to_string();
    info!("read td: {}", path);
    let data = fs::read(path).unwrap();
    event_data.push(data);

    let path = "/sys/firmware/acpi/tables/data/TDEL".to_string();
    info!("read td: {}", path);
    let data = fs::read(path).unwrap();
    event_data.push(data);

    eventlog_rs::dump(event_data, eventlog_rs::TEE_TDX);
}
