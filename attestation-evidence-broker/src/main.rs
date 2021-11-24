use anyhow::Result;
use clap::{crate_authors, crate_version, App, Arg};
use ttrpc_server::rpc_server;

mod aeb_modules;
mod device_type;
mod protocols;
mod ttrpc_server;

#[macro_use]
extern crate log;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter(None, log::LevelFilter::Debug)
        .init();

    let matches = App::new("Attestation Evidence Broker")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Attestation Evidence Broker for provide evidence for guest attestation agent")
        .arg(
            Arg::with_name("listen")
                .long("listen")
                .short("l")
                .help("Specify the socket listen addr. For example: vsock:///tmp/aeb.sock, unix:///tmp/aeb.sock")
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

    debug!("starting Attestation Evidence Broker service...");

    rpc_server::start_service(sockaddr, listen_port).await?;

    Ok(())
}
