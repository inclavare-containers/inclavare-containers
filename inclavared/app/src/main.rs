/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate sgx_types;
extern crate sgx_urts;

use std::thread;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::net::{UnixStream, UnixListener};
use std::net::{SocketAddr, TcpStream, TcpListener};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::Arc;
use libc::{c_void};
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use clap::{Arg, App};
use serde_json::json;
use sgx_types::{
    SgxResult, sgx_attributes_t, sgx_launch_token_t, sgx_misc_attribute_t
};
use sgx_urts::SgxEnclave;

#[macro_use]
extern crate log;

include!("ffi.rs");
include!("enclave-tls.rs");


fn sgx_enclave_create(file: &str) -> SgxResult<SgxEnclave> {
    let debug = 1;
    let mut token: sgx_launch_token_t = [0; 1024];
    let mut updated: i32 = 0;
    let mut attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(file, debug, &mut token, &mut updated, &mut attr)
}

fn enclave_info_fetch(sockfd: RawFd, buf: &mut [u8],
                tls_type: &Option<String>, crypto: &Option<String>,
                attester: &Option<String>, verifier: &Option<String>,
                mutual: bool, enclavefile: &String) -> usize {
    /* TODO: use one enclave */
    let enclave = match sgx_enclave_create(enclavefile) {
        Ok(r) => r,
        Err(e) => {
            error!("sgx_enclave_create() failed, {}", e.as_str());
            return 0;
        }
    };

    let tls = EnclaveTls::new(false, enclave.geteid(),
                tls_type, crypto, attester, verifier, mutual).unwrap();

    /* connect */
    tls.negotiate(sockfd).unwrap();

    let n = tls.transmit(b"hello from inclavared").unwrap();
    assert!(n > 0);

    let n = tls.receive(buf).unwrap();

    /* XXX TODO: tls must be droped before enclave */
    drop(tls);
    enclave.destroy();

    n
}

fn client_fetch(sockaddr: &str, buf: &mut [u8],
                tls_type: &Option<String>, crypto: &Option<String>,
                attester: &Option<String>, verifier: &Option<String>,
                mutual: bool, enclavefile: &String) -> usize {
    let addr = sockaddr.parse::<SocketAddr>();
    if addr.is_err() {
        /* unix socket */
        let stream = UnixStream::connect(sockaddr).unwrap();
        enclave_info_fetch(stream.as_raw_fd(), buf,
                tls_type, crypto, attester, verifier, mutual, enclavefile)
    } else {
        let stream = TcpStream::connect(sockaddr).unwrap();
        enclave_info_fetch(stream.as_raw_fd(), buf,
                tls_type, crypto, attester, verifier, mutual, enclavefile)
    }
}

fn handle_client(sockfd: RawFd, upstream: &Option<String>,
                tls_type: &Option<String>, crypto: &Option<String>,
                attester: &Option<String>, verifier: &Option<String>,
                mutual: bool, enclavefile: &String) {
    let enclave = match sgx_enclave_create(enclavefile) {
        Ok(r) => r,
        Err(e) => {
            error!("sgx_enclave_create() failed, {}", e.as_str());
            return;
        }
    };

    /* XXX: mutual is always false */
    let tls = EnclaveTls::new(true, enclave.geteid(),
                tls_type, crypto, attester, verifier, false).unwrap();

    /* accept */
    tls.negotiate(sockfd).unwrap();

    /* get client request */
    let mut buffer = [0u8; 512];
    let n = tls.receive(&mut buffer).unwrap();
    info!("req: {}", String::from_utf8((&buffer[..n]).to_vec()).unwrap());

    if let Some(upstream) = upstream {
        /* fetch enclave information from upstream */
        let n = client_fetch(&upstream, &mut buffer,
                    tls_type, crypto, attester, verifier, mutual, enclavefile);
        info!("message length from upstream: {}", n);

        /* TODO: shit code */
        let resp = if n > 64 {
            let mrenclave = &buffer[0..32];
            let mrsigner = &buffer[32..64];
            let message = String::from_utf8((&buffer[64..n]).to_vec()).unwrap();
            info!("message from upstream: {}", message);

            let resp = json!({
                "id": "123456",
                "msgtype": "ENCLAVEINFO",
                "version": 1,
                "mrenclave": hex::encode(mrenclave),
                "mrsigner": hex::encode(mrsigner),
                "message": message
            });
            resp.to_string()
        } else if n > 0 {
            String::from_utf8((&buffer[..n]).to_vec()).unwrap()
        } else {
            String::from("reply from inclavared!\n")
        };
        info!("resp: {}", resp);

        /* response reply */
        tls.transmit(resp.as_bytes()).unwrap();
    } else {
        let n = tls.transmit(b"reply from inclavared!\n").unwrap();
        assert!(n > 0);
    }

    /* XXX TODO: tls must be droped before enclave */
    drop(tls);
    enclave.destroy();
}

fn run_server(sockaddr: &str, upstream: Option<String>,
            tls_type: Option<String>, crypto: Option<String>,
            attester: Option<String>, verifier: Option<String>,
            mutual: bool, enclavefile: String) {
    let upstream = Arc::new(upstream);
    let tls_type = Arc::new(tls_type);
    let crypto = Arc::new(crypto);
    let attester = Arc::new(attester);
    let verifier = Arc::new(verifier);
    let enclavefile = Arc::new(enclavefile);
    let addr = sockaddr.parse::<SocketAddr>();
    /* TODO: Abstract together */
    if addr.is_err() {
        /* unix socket */
        let _ = std::fs::remove_file(sockaddr);
        let listener = UnixListener::bind(sockaddr).unwrap();
        loop {
            let (socket, addr) = listener.accept().unwrap();
            info!("thread for {:?}", addr);
            let upstream = upstream.clone();
            let tls_type = tls_type.clone();
            let crypto = crypto.clone();
            let attester = attester.clone();
            let verifier = verifier.clone();
            let enclavefile = enclavefile.clone();
            thread::spawn(move || {
                handle_client(socket.as_raw_fd(), &upstream, &tls_type,
                    &crypto, &attester, &verifier, mutual, &enclavefile);
            });
        }
    } else {
        /* tcp */
        let listener = TcpListener::bind(sockaddr).unwrap();
        loop {
            let (socket, addr) = listener.accept().unwrap();
            info!("thread for {:?}", addr);
            let upstream = upstream.clone();
            let tls_type = tls_type.clone();
            let crypto = crypto.clone();
            let attester = attester.clone();
            let verifier = verifier.clone();
            let enclavefile = enclavefile.clone();
            thread::spawn(move || {
                handle_client(socket.as_raw_fd(), &upstream, &tls_type,
                    &crypto, &attester, &verifier, mutual, &enclavefile);
            });
        }
    }
}

fn main() {
    env_logger::builder().filter(None, log::LevelFilter::Trace).init();

    let matches = App::new("inclavared")
                    .version("0.1")
                    .author("Inclavare-Containers Team")
                    .arg(Arg::with_name("listen")
                        .short("l")
                        .long("listen")
                        .value_name("sockaddr")
                        .help("Work in listen mode")
                        .takes_value(true)
                    )
                    .arg(Arg::with_name("xfer")
                        .short("x")
                        .long("xfer")
                        .value_name("sockaddr")
                        .help("Xfer data from client to server")
                        .takes_value(true)
                    )
                    .arg(Arg::with_name("connect")
                        .short("c")
                        .long("connect")
                        .value_name("sockaddr")
                        .help("Work in client mode")
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
                    .arg(Arg::with_name("enclave")
                        .short("e")
                        .long("enclave")
                        .value_name("file")
                        .help("Specify the enclave file")
                        .takes_value(true)
                    )
                    .get_matches();

    info!("enter");

    let tls_type = matches.value_of("tls").map(|s| s.to_string());
    let crypto = matches.value_of("crypto").map(|s| s.to_string());
    let attester = matches.value_of("attester").map(|s| s.to_string());
    let verifier = matches.value_of("verifier").map(|s| s.to_string());
    let mutual = matches.is_present("mutual");

    let enclavefile = matches.value_of("enclave")
                .unwrap_or("/opt/enclave-tls/bin/sgx_stub_enclave.signed.so");
    let enclavefile = enclavefile.to_string();

    if matches.is_present("listen") {
        let sockaddr = matches.value_of("listen").unwrap();
        let xfer = matches.value_of("xfer").map(|s| s.to_string());

        run_server(sockaddr, xfer,
                tls_type, crypto, attester, verifier, mutual, enclavefile);
    } else {
        let sockaddr = matches.value_of("connect").unwrap();

        let mut buffer = [0u8; 512];
        let n = client_fetch(sockaddr, &mut buffer,
                    &tls_type, &crypto, &attester, &verifier, mutual, &enclavefile);
        assert!(n > 0);
        info!("length from upstream: {}", n);

        let message = String::from_utf8((&buffer[64..]).to_vec()).unwrap();
        info!("message from upstream: {}", message);
    }

    info!("leave");
}
