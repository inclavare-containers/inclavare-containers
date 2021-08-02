
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::thread;
use std::os::unix::io::{RawFd, AsRawFd};
use std::net::{SocketAddr, TcpStream, TcpListener};
use parking_lot::RwLock;
use std::{sync::Arc, u64};
use serde::{Serialize, Deserialize};
use serde_json::json;
use serde_json::Value;

mod key_manager;
mod key_provider;
mod crypto;
mod enclave_tls;
mod policyEngine;
mod protocol;

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

fn run_server(sockaddr: &str) {
    let tls_type = Arc::new(Some("openssl".to_string()));
    let crypto = Arc::new(Some("openssl".to_string()));
    let attester = Arc::new(Some("nullattester".to_string()));
    let verifier = Arc::new(Some("sgx_ecdsa".to_string()));
    let addr = sockaddr.parse::<SocketAddr>();

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
                &crypto, &attester, &verifier, true, 0);
        });
    }
}

#[tokio::main]
async fn main() {
    println!("Verdictd Server Started ...");

    thread::spawn(move || {
        println!("Launch server with port 1122");
        run_server("127.0.0.1:1122");
    });

    // Launch gRPC server
    println!("Launch gRPC server");
    let addr = "[::1]:50000";
    let key_provider_server = key_provider::key_provider_grpc::key_provider_server(&addr);
    key_provider_server.await;
}
