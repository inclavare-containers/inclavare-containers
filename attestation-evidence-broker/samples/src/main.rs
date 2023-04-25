use anyhow::Result;
use clap::{crate_authors, crate_version, App, Arg};

mod sev_aeb;
mod ttrpc_client;

#[macro_use]
extern crate log;

fn main() -> Result<()> {
    env_logger::builder()
        .filter(None, log::LevelFilter::Debug)
        .init();

    let matches = App::new("Sample attester")
        .version(crate_version!())
        .author(crate_authors!())
        .about("A sample attester connecting to AEB to query SEV attestation evidence")
        .arg(
            Arg::with_name("connect")
                .long("connect")
                .short("c")
                .help("Specify the socket connect addr. For example: vsock:///tmp/aeb.sock, unix:///tmp/aeb.sock")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .help("Specify the socket listen port. Default is 5577")
                .takes_value(true),
        )
        .get_matches();

    let sockaddr = match matches.is_present("listen") {
        true => matches
            .value_of("listen")
            .expect("port is required")
            .to_string(),
        false => "vsock:///tmp/aeb.sock".to_string(),
    };
    let listen_port = match matches.is_present("port") {
        true => matches
            .value_of("port")
            .expect("port is required")
            .parse::<u16>()?,
        false => 5577,
    };

    debug!("Sample Attester connecting to Attestation Evidence Broker service");

    ttrpc_client::rpc_client::connect_service(sockaddr, listen_port)?;

    Ok(())
}
