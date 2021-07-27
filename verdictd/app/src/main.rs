
use std::error::Error;
use std::{thread, usize};
use std::os::unix::io::{RawFd, AsRawFd};
use std::net::{SocketAddr, TcpStream, TcpListener};
use parking_lot::RwLock;
use std::{sync::Arc, u64};
use serde::{Serialize, Deserialize};
use serde_json::json;
use serde_json::Value;

mod key_manager;
mod enclave_tls;
mod policyEngine;

fn parse_aa_request_and_generate_response(request: &[u8]) -> Result<String, String> {
    let parsed_request: Value = match serde_json::from_slice(request) {
        Ok(r) => r,
        Err(e) => {
            println!("Error: json::from_slice() failed, {}", e);
            return Err("parse request failed".to_string());
        }
    };

    match parsed_request["command"].as_str().unwrap() {
        "version" => {
            let response = json!({
                "status": "OK",
                "version": "v1",
            });
            return Ok(response.to_string());
        }
        _ => println!("Error: command not found")
    }

    Err("command error".to_string())
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
        println!("tls_negotiate() failed, sockfd = {}", sockfd);
        return;
    }

    /* get client request */
    let mut buffer = [0u8; 512];
    let n = tls.receive(&mut buffer).unwrap();
    println!("Request: {}", String::from_utf8((&buffer[..n]).to_vec()).unwrap());

    let response = match parse_aa_request_and_generate_response(&buffer[..n]) {
        Ok(response) => response,
        Err(e) => {
            let response = json!({
                "status": "Fail",
                "error": e
            });
            response.to_string()
        }
    };
    println!("response: {}", response);

    let n = tls.transmit(&buffer[..n]).unwrap();
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

    run_server("127.0.0.1:1122");
}
