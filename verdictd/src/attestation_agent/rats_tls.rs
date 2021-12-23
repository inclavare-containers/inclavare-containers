use crate::attestation_agent::protocol;
use crate::rats_tls;
use std::net::TcpListener;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{sync::Arc, u64};

pub const ACTION_NONE: u8 = 0;
pub const ACTION_DISCONNECT: u8 = 1;

fn handle_client(
    sockfd: RawFd,
    tls_type: &Option<String>,
    crypto: &Option<String>,
    attester: &Option<String>,
    verifier: &Option<String>,
    mutual: bool,
    enclave_id: u64,
) -> Result<(), String> {
    let tls = rats_tls::RatsTls::new(
        true, enclave_id, tls_type, crypto, attester, verifier, mutual,
    )
    .map_err(|e| format!("new RatsTls failed with error {:?}", e))?;

    /* accept */
    if tls.negotiate(sockfd).is_err() {
        return Err(format!("tls_negotiate() failed, sockfd = {}", sockfd));
    }

    loop {
        /* get client request */
        let mut buffer = [0u8; 4096];

        let n = tls.receive(&mut buffer)
            .map_err(|e| format!("tls client disconnect, code: {:?}", e))?;

        let (response, action) = protocol::handle(&buffer[..n])
            .map_err(|e| format!("handle request err: {} sockfd:{}", e, sockfd))?;
        info!("response: {}", response);

        tls.transmit(response.as_bytes())
            .map_err(|e| format!("tls transmit error: {:?}", e))?;

        if action == ACTION_DISCONNECT {
            return Ok(());
        }
    }
}

pub fn server(
    sockaddr: &str,
    tls_type: String,
    crypto: String,
    attester: String,
    verifier: String,
    mutual: bool,
) {
    let tls_type = Arc::new(Some(tls_type));
    let crypto = Arc::new(Some(crypto));
    let attester = Arc::new(Some(attester));
    let verifier = Arc::new(Some(verifier));

    /* tcp */
    let listener = TcpListener::bind(sockaddr).unwrap();
    loop {
        let (socket, addr) = listener.accept().unwrap();
        info!("thread for {} {:?}", socket.as_raw_fd(), addr);
        let tls_type = tls_type.clone();
        let crypto = crypto.clone();
        let attester = attester.clone();
        let verifier = verifier.clone();
        std::thread::spawn(move || {
            match handle_client(
                socket.as_raw_fd(),
                &tls_type,
                &crypto,
                &attester,
                &verifier,
                mutual,
                0,
            ) {
                Ok(_) => {},
                Err(e) => error!("{}", e),
            }
        });
    }
}
