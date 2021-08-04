
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::thread;
use std::os::unix::io::{RawFd, AsRawFd};
use std::net::TcpListener;
use std::{sync::Arc, u64};
use serde_json::json;
use shadow_rs::shadow;
use clap::{Arg, App};

mod key_manager;
mod key_provider;
mod crypto;
mod enclave_tls;
mod policyEngine;
mod protocol;

shadow!(build);

const POLICY_PATH: &str = "/opt/verdictd/opa/policy/";

fn set_default_policy() -> Result<(), String>{
    let res = match std::path::Path::new(&POLICY_PATH.to_string()).exists() {
        false => {
            std::fs::create_dir_all(POLICY_PATH)
                .map_err(|_| format!("create {:?} failed", POLICY_PATH))
        },
        true => Ok(()),
    };
    match res {
        Err(e) => return Err(e),
        Ok(_) => {},
    }

    let res = match std::path::Path::new(&(POLICY_PATH.to_string() + "attestation.rego")).exists() {
        false => {
            println!("attestation.rego isn't exist");
            let reference = json!({
                "mrEnclave": "123",
                "mrSigner": "4569",
                "productId": "1",
            });  
            match policyEngine::opa::opaEngine::set_reference("attestation.rego", &reference.to_string()){
                true => Ok(()),
                false => Err("Set attestation.rego policy failed".to_string()),
            }                    
        },
        true => Ok(()),
    };
    match res {
        Err(e) => return Err(e),
        Ok(_) => {},
    }    

    Ok(())
}

fn handle_client(sockfd: RawFd,
    tls_type: &Option<String>, crypto: &Option<String>,
    attester: &Option<String>, verifier: &Option<String>,
    mutual: bool, enclave_id: u64) {
    let tls = match enclave_tls::EnclaveTls::new(true, enclave_id, tls_type,
                        crypto, attester, verifier, mutual) {
        Ok(r) => r,
        Err(_e) => {
            return;
        }
    };

    /* accept */
    if tls.negotiate(sockfd).is_err() {
        print!("tls_negotiate() failed, sockfd = {}", sockfd);
        return;
    }

    /* get client request */
    let mut buffer = [0u8; 4096];
    let n = tls.receive(&mut buffer).unwrap();
    let response = match protocol::handle_aa_request(&buffer[..n]) {
        Ok(response) => response,
        Err(e) => {
            let response = json!({
                "status": "Fail",
                "error": e
            });
            response.to_string()
        }
    };

    let n = tls.transmit(response.as_bytes()).unwrap();
    assert!(n > 0);
}

fn run_server(sockaddr: &str, tls_type: String, crypto: String, attester: String, verifier: String, mutual: bool) {
    let tls_type = Arc::new(Some(tls_type));
    let crypto = Arc::new(Some(crypto));
    let attester = Arc::new(Some(attester));
    let verifier = Arc::new(Some(verifier));

    /* tcp */
    let listener = TcpListener::bind(sockaddr).unwrap();
    loop {
        let (socket, addr) = listener.accept().unwrap();
        println!("thread for {} {:?}", socket.as_raw_fd(), addr);
        let tls_type = tls_type.clone();
        let crypto = crypto.clone();
        let attester = attester.clone();
        let verifier = verifier.clone();
        thread::spawn(move || {
            handle_client(socket.as_raw_fd(), &tls_type,
                &crypto, &attester, &verifier, mutual, 0);
        });
    }
}

#[tokio::main]
async fn main() {
    let version = format!("v{}\ncommit: {}\nbuildtime: {}",
                    build::PKG_VERSION, build::COMMIT_HASH, build::BUILD_TIME);
    println!("Verdictd info: {}", version);

    match set_default_policy() {
        Ok(_) => {},
        Err(e) => {
            println!("error: {}", e);
            return;
        }
    }

    let matches = 
        App::new("verdictd")
            .version(version.as_str())
                .long_version(version.as_str())
                .author("Inclavare-Containers Team")
                .arg(Arg::with_name("listen")
                    .short("l")
                    .long("listen")
                    .value_name("sockaddr")
                    .help("Work in listen mode")
                    .takes_value(true)
                )
                .arg(Arg::with_name("tls")
                    .long("tls")
                    .value_name("tls_type")
                    .help("Specify the TLS type")
                    .takes_value(true)
                )
                .arg(Arg::with_name("crypto")
                    .long("crypto")
                    .value_name("crypto_type")
                    .help("Specify the crypto type")
                    .takes_value(true)
                )   
                .arg(Arg::with_name("attester")
                    .long("attester")
                    .value_name("attester_type")
                    .help("Specify the attester type")
                    .takes_value(true)
                )
                .arg(Arg::with_name("verifier")
                    .long("verifier")
                    .value_name("verifier_type")
                    .help("Specify the verifier type")
                    .takes_value(true)
                )
                .arg(Arg::with_name("mutual")
                    .short("m")
                    .long("mutual")
                    .help("Work in mutual mode")
                )                
                .arg(Arg::with_name("gRPC")
                    .long("gRPC")
                    .value_name("gRPC_addr")
                    .help("Specify the gRPC listen addr")
                    .takes_value(true)
                )                                  
                .get_matches();

    let sockaddr = match matches.is_present("listen") {
        true => matches.value_of("listen").unwrap().to_string(),
        false => "127.0.0.1:1234".to_string(),
    };
    let tls_type = match matches.is_present("tls") {
        true => matches.value_of("tls").unwrap().to_string(),
        false => "openssl".to_string(),
    };   
    let crypto = match matches.is_present("crypto") {
        true => matches.value_of("crypto").unwrap().to_string(),
        false => "openssl".to_string(),
    };   
    let attester = match matches.is_present("attester") {
        true => matches.value_of("attester").unwrap().to_string(),
        false => "nullattester".to_string(),
    }; 
    let verifier = match matches.is_present("verifier") {
        true => matches.value_of("verifier").unwrap().to_string(),
        false => "sgx_ecdsa".to_string(),
    };
    let mutual = matches.is_present("mutual");   
    thread::spawn(move || {
        println!("Listen addr: {}", sockaddr);
        run_server(&sockaddr, tls_type, crypto, attester, verifier, mutual);
    });

    // Launch gRPC server
    let gRPC_addr = match matches.is_present("gRPC") {
        true => matches.value_of("gRPC").unwrap().to_string(),
        false => "[::1]:50000".to_string(),
    };      
    println!("Listen gRPC server addr: {}", gRPC_addr);
    let key_provider_server = key_provider::key_provider_grpc::key_provider_server(&gRPC_addr);
    match key_provider_server.await{
        Ok(_) => {},
        Err(_) => println!("key_provider_server launch failed."),
    }
}
