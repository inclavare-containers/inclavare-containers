use crate::attestation_agent::protocol;
use crate::enclave_tls;
use rayon;
use serde_json::json;
use std::net::TcpListener;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{sync::Arc, u64};

fn handle_client(
    sockfd: RawFd,
    tls_type: &Option<String>,
    crypto: &Option<String>,
    attester: &Option<String>,
    verifier: &Option<String>,
    mutual: bool,
    enclave_id: u64,
) {
    let tls = match enclave_tls::EnclaveTls::new(
        true, enclave_id, tls_type, crypto, attester, verifier, mutual,
    ) {
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
    let response = protocol::handle_aa_request(&buffer[..n]).unwrap_or_else(|e| {
        json!({
            "status": "Fail",
            "error": e
        })
        .to_string()
    });

    let n = tls.transmit(response.as_bytes()).unwrap();
    assert!(n > 0);
}

pub fn server(
    sockaddr: &str,
    tls_type: String,
    crypto: String,
    attester: String,
    verifier: String,
    mutual: bool,
) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build()
        .unwrap();

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
        pool.spawn(move || {
            println!(
                "##### Task executes on thread: {:?} #####",
                std::thread::current().id()
            );
            handle_client(
                socket.as_raw_fd(),
                &tls_type,
                &crypto,
                &attester,
                &verifier,
                mutual,
                0,
            );
        });
    }
}
