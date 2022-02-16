#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use clap::{App, Arg};
use shadow_rs::shadow;
use policy_engine::*;
use resources::*;

mod attestation_agent;
mod client_api;
mod crypto;
mod rats_tls;
mod resources;
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
            error!("opa: {}", e);
            return;
        }
    }

    match gpg::default() {
        Ok(_) => {}
        Err(e) => {
            error!("gpg: {}", e);
            return;
        }
    }

    match image::default() {
        Ok(_) => {}
        Err(e) => {
            error!("image: {}", e);
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
            Arg::with_name("client_api")
                .long("client-api")
                .value_name("client_api")
                .help("Specify the client API's listen addr")
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

     // Launch client API gRPC server
     let client_api = match matches.is_present("client_api") {
        true => matches.value_of("client_api").unwrap().to_string(),
        false => "[::1]:60000".to_string(),
    };
    info!("Listen client API server addr: {}", client_api);
    let client_api_server = client_api::api::server(&client_api);
    match client_api_server.await {
        Ok(_) => info!("Success"),
        Err(e) => info!("Launch client API service failed with: {}", e.to_string()),
    }
}
