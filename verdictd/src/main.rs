#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use clap::{App, Arg};
use shadow_rs::shadow;
use policy_engine::*;

mod attestation_agent;
mod configure_provider;
mod crypto;
mod rats_tls;
mod key_manager;
mod key_provider;
mod policy_engine;

#[macro_use]
extern crate log;

shadow!(build);

#[tokio::main]
async fn main() {
    env_logger::builder().filter(None, log::LevelFilter::Info).init();

    let version = format!(
        "v{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
    info!("Verdictd info: {}", version);

    match opa::opa_engine::default() {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            return;
        }
    }

    let matches = App::new("verdictd")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Inclavare-Containers Team")
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("sockaddr")
                .help("Work in listen mode")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls")
                .long("tls")
                .value_name("tls_type")
                .help("Specify the TLS type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("crypto")
                .long("crypto")
                .value_name("crypto_type")
                .help("Specify the crypto type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("attester")
                .long("attester")
                .value_name("attester_type")
                .help("Specify the attester type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verifier")
                .long("verifier")
                .value_name("verifier_type")
                .help("Specify the verifier type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mutual")
                .short("m")
                .long("mutual")
                .help("Work in mutual mode"),
        )
        .arg(
            Arg::with_name("gRPC")
                .long("gRPC")
                .value_name("gRPC_addr")
                .help("Specify the gRPC listen addr")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .value_name("config_addr")
                .help("Specify the config listen addr")
                .takes_value(true),
        )        
        .get_matches();

    let sockaddr = match matches.is_present("listen") {
        true => matches.value_of("listen").unwrap().to_string(),
        false => "127.0.0.1:1234".to_string(),
    };
    let tls_type = match matches.is_present("tls") {
        true => matches.value_of("tls").unwrap().to_string(),
        false => "".to_string(),
    };
    let crypto = match matches.is_present("crypto") {
        true => matches.value_of("crypto").unwrap().to_string(),
        false => "".to_string(),
    };
    let attester = match matches.is_present("attester") {
        true => matches.value_of("attester").unwrap().to_string(),
        false => "".to_string(),
    };
    let verifier = match matches.is_present("verifier") {
        true => matches.value_of("verifier").unwrap().to_string(),
        false => "".to_string(),
    };

    let mutual = matches.is_present("mutual");
    std::thread::spawn(move || {
        info!("Listen addr: {}", sockaddr);
        attestation_agent::rats_tls::server(
            &sockaddr, tls_type, crypto, attester, verifier, mutual,
        );
    });

    // Launch wrap/unwrap gRPC server
    let gRPC_addr = match matches.is_present("gRPC") {
        true => matches.value_of("gRPC").unwrap().to_string(),
        false => "[::1]:50000".to_string(),
    };
    info!("Listen gRPC server addr: {}", gRPC_addr);
    let key_provider_server = key_provider::key_provider_grpc::server(&gRPC_addr);

     // Launch configuration gRPC server
     let config_addr = match matches.is_present("config") {
        true => matches.value_of("config").unwrap().to_string(),
        false => "[::1]:60000".to_string(),
    };
    info!("Listen configuration server addr: {}", config_addr);
    let config_provider_server = configure_provider::provider::server(&config_addr);

    let (_first, _second) = tokio::join!(key_provider_server, config_provider_server);
}
