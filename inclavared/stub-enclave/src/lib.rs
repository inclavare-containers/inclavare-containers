// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "stub"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_tcrypto_helper;
extern crate sgx_trts;
extern crate sgx_tse;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate rustls;
extern crate webpki;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate serde_json;
extern crate chrono;
extern crate webpki_roots;
extern crate ring;
extern crate num_bigint;

use std::backtrace::{self, PrintFormat};
use sgx_types::*;
use sgx_tse::*;
//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_tcrypto::*;
use sgx_rand::*;

use core::convert::TryInto;

use std::prelude::v1::*;
use std::sync::Arc;
use std::net::TcpStream;
use std::string::String;
use std::io;
use std::ptr;
use std::str;
use std::env;
use std::io::{Write, Read};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;
use sgx_tcrypto_helper::RsaKeyPair;
use sgx_tcrypto_helper::rsa3072::SGX_RSA3072_DEFAULT_E;
use yasna::DEREncodable;
use bit_vec::BitVec;

mod cert;
mod hex;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

extern "C" {
    pub fn ocall_sgx_init_quote(ret_val: *mut sgx_status_t,
                                ret_ti: *mut sgx_target_info_t,
                                ret_gid: *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t,
                                ret_fd: *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote(ret_val: *mut sgx_status_t,
                           p_sigrl: *const u8,
                           sigrl_len: u32,
                           p_report: *const sgx_report_t,
                           quote_type: sgx_quote_sign_type_t,
                           p_spid: *const sgx_spid_t,
                           p_nonce: *const sgx_quote_nonce_t,
                           p_qe_report: *mut sgx_report_t,
                           p_quote: *mut u8,
                           maxlen: u32,
                           p_quote_len: *mut u32) -> sgx_status_t;
}


fn parse_response_attn_report(resp: &[u8]) -> (String, String, String, String) {
    println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => {
            println!("DBG:{}", respp.code.unwrap());
            msg = "Unknown error occured"
        }
    }

    println!("{}", msg);
    let mut len_num: u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name {
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();

    let mut sig_cert_ca = String::from("-----BEGIN CERTIFICATE-----\n");
    sig_cert_ca.push_str(v[2]);
    sig_cert_ca.push_str("\n-----END CERTIFICATE-----");

    let mut sig_cert = String::from("-----BEGIN CERTIFICATE-----\n");
    sig_cert.push_str(v[6]);
    sig_cert.push_str("\n-----END CERTIFICATE-----");

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert_ca, sig_cert)
}


fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
    println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);
    println!("parse response{:?}", respp);

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => msg = "Unknown error occured",
    }

    println!("{}", msg);
    let mut len_num: u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "Content-Length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}


pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> Vec<u8> {
    println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();
    let ias_key = get_ias_api_key().unwrap();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                      SIGRL_SUFFIX,
                      gid,
                      DEV_HOSTNAME,
                      ias_key);
    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> (String, String, String, String) {
    println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let ias_key = get_ias_api_key().unwrap();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                      REPORT_SUFFIX,
                      DEV_HOSTNAME,
                      ias_key,
                      encoded_json.len(),
                      encoded_json);
    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert_ca, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert_ca, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0) +
        ((array[1] as u32) << 8) +
        ((array[2] as u32) << 16) +
        ((array[3] as u32) << 24)
}

#[allow(const_err)]
// pub fn create_attestation_report(pub_k: &sgx_ec256_public_t, sign_type: sgx_quote_sign_type_t)
pub fn create_attestation_report(pub_k: &sgx_rsa3072_public_key_t)
// pub fn create_attestation_report(mod_size: i32, exp_size: i32, n: &[u8], e: &[u8], sign_type: sgx_quote_sign_type_t)
                                 -> Result<(String, String, String, String), sgx_status_t> {

    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t)
    };

    println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = 0;

    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    // let mut pub_k_gx = pub_k.gx.clone();
    // pub_k_gx.reverse();
    // let mut pub_k_gy = pub_k.gy.clone();
    // pub_k_gy.reverse();

    // let mut pub_k_m = pub_k.modulus.clone();
    // let mut pub_k_e = pub_k.exponent.clone();
    // let mut pub_k_n = n.clone();
    // let mut pub_k_e = e.clone();
    // pub_k_n.reverse();
    // pub_k_e.reverse();

    let mut pub_key_bytes: Vec<u8> = vec![4];
    let mut pk_m = pub_k.modulus.clone();
    let mut pk_e = pub_k.exponent.clone();
    pk_m.reverse();
    pk_e.reverse();
    pub_key_bytes.extend_from_slice(&pk_m);
    pub_key_bytes.extend_from_slice(&pk_e);

    // let pk = SgxRsaPubKey::new();
    // pk.create(mod_size, exp_size, n, e).unwrap();

    let der = yasna::construct_der(|writer| {
        writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
    });

    let pub_k_hash = rsgx_sha256_slice(&der).unwrap();
    report_data.d[..32].clone_from_slice(&pub_k_hash);
    // report_data.d[32..].clone_from_slice(&pub_k_e);


    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        }
        Err(e) => {
            println!("Report creation => failed {:?}", e);
            None
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    let p_report = (&rep.unwrap()) as *const sgx_report_t;

    let quote_type = load_quote_type().map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    let spid: sgx_spid_t = load_spid().map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(&mut rt as *mut sgx_status_t,
                        p_sigrl,
                        sigrl_len,
                        p_report,
                        quote_type,
                        p_spid,
                        p_nonce,
                        p_qe_report,
                        p_quote,
                        maxlen,
                        p_quote_len)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("rsgx_verify_report passed!"),
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
        ti.attributes.flags != qe_report.body.attributes.flags ||
        ti.attributes.xfrm != qe_report.body.attributes.xfrm {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert_ca, cert) = get_report_from_intel(ias_sock, quote_vec);
    Ok((attn_report, sig, cert_ca, cert))
}

fn load_quote_type() -> Result<sgx_quote_sign_type_t, &'static str> {
    let spidstr = env::var_os("QUOTE_TYPE")
        .ok_or("ENV QUOTE_TYPE MUST BE SET")?
        .to_str().ok_or("QUOTE_TYPE can not be convert to &str")?
        .to_string();

    match spidstr.as_str() {
        "SGX_UNLINKABLE_SIGNATURE" => Ok(sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE),
        "SGX_LINKABLE_SIGNATURE" => Ok(sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE),
        _ => Err("bad quote type, valid quote types: [\"SGX_LINKABLE_SIGNATURE\", \"SGX_UNLINKABLE_SIGNATURE\"]")
    }
}

fn load_spid() -> Result<sgx_spid_t, &'static str> {
    let spidstr = env::var_os("SPID")
        .ok_or("ENV SPID MUST BE SET")?
        .to_str().ok_or("SPID can not be convert to &str")?
        .to_string();

    Ok(hex::decode_spid(spidstr))
}

fn get_ias_api_key() -> Result<String, &'static str> {
    let spidstr = env::var_os("EPID_SUBSCRIPTION_KEY")
        .ok_or("ENV EPID_SUBSCRIPTION_KEY MUST BE SET")?
        .to_str().ok_or("EPID_SUBSCRIPTION_KEY can not be convert to &str")?
        .trim_end()
        .to_string();

    Ok(spidstr)
}

struct ClientAuth {
    outdated_ok: bool,
}

impl ClientAuth {
    fn new(outdated_ok: bool) -> ClientAuth {
        ClientAuth { outdated_ok: outdated_ok }
    }
}

impl rustls::ClientCertVerifier for ClientAuth {
    fn client_auth_root_subjects(&self) -> rustls::DistinguishedNames {
        rustls::DistinguishedNames::new()
    }

    fn verify_client_cert(&self, _certs: &[rustls::Certificate])
                          -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        println!("client cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ClientCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ClientCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
            }
        }
    }
}

struct ServerAuth {
    outdated_ok: bool
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth { outdated_ok: outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate],
                          _hostname: webpki::DNSNameRef,
                          _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("server cert: {:?}", _certs);

        println!("{:?}", fs::File::create("./tls_server.der").unwrap().write(_certs[0].as_ref()));

        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ServerCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ServerCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn run_server(socket_fd: c_int) -> sgx_status_t {
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

    // Generate Keypair
    // let ecc_handle = SgxEccHandle::new();
    // let _result = ecc_handle.open();
    // let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    // let kpair = sgx_tcrypto_helper::rsa3072::Rsa3072KeyPair::new().unwrap();
    // let prv_k= kpair.to_privkey().unwrap();
    // let pub_k = kpair.to_pubkey().unwrap();

    let mod_size: i32 = SGX_RSA3072_KEY_SIZE as i32;
    let exp_size: i32 = SGX_RSA3072_PUB_EXP_SIZE as i32;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    rsgx_create_rsa_key_pair(mod_size,
                             exp_size,
                             n.as_mut_slice(),
                             d.as_mut_slice(),
                             e.as_mut_slice(),
                             p.as_mut_slice(),
                             q.as_mut_slice(),
                             dmp1.as_mut_slice(),
                             dmq1.as_mut_slice(),
                             iqmp.as_mut_slice()).unwrap();

    let cn = n.clone();
    let ce = e.clone();
    let cd = d.clone();
    let cp = p.clone();
    let cq = q.clone();
    let cdmp1 = dmp1.clone();
    let cdmq1 = dmq1.clone();
    let ciqmp = iqmp.clone();


    let args = &[cn.as_slice(),
        ce.as_slice(),
        cd.as_slice(),
        cp.as_slice(),
        cq.as_slice(),
        cdmp1.as_slice(),
        cdmq1.as_slice(),
        ciqmp.as_slice()];

    let n_slice = n.into_boxed_slice();
    let n_array: Box<[u8; SGX_RSA3072_KEY_SIZE]> = match n_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 4, o.len()),
    };

    let e_slice = e.into_boxed_slice();
    let e_array: Box<[u8; SGX_RSA3072_PUB_EXP_SIZE]> = match e_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 4, o.len()),
    };

    let d_slice = d.into_boxed_slice();
    let d_array: Box<[u8; SGX_RSA3072_KEY_SIZE]> = match d_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 4, o.len()),
    };

    let pub_k = sgx_rsa3072_public_key_t {
        modulus: *n_array,
        exponent: *e_array,
    };

    let prv_k = sgx_rsa3072_key_t {
        modulus: *n_array,
        d: *d_array,
        e: *e_array,
    };

    let (attn_report, sig, cert_ca, cert) = match create_attestation_report(&pub_k) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    // let payload = attn_report + "|" + &sig + "|" + &cert;
    let payloads = [attn_report, sig, cert_ca, cert];
    //let (key_der, cert_der) = match cert::gen_ecc_cert(&payloads, &prv_k, &pub_k, &ecc_handle) {
    let (key_der, cert_der) = match cert::gen_rsa_cert(&payloads, &prv_k, &pub_k, args) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_rsa3072_cert: {:?}", e);
            return e;
        }
    };
    // let _result = ecc_handle.close();


    let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true)));
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    ring::signature::RsaKeyPair::from_der(&privkey.0).unwrap();

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut plaintext = [0u8; 1024]; //Vec::new();
    match tls.read(&mut plaintext) {
        Ok(_) => println!("Client said: {}", str::from_utf8(&plaintext).unwrap()),
        Err(e) => {
            println!("Error in read_to_end: {:?}", e);
            panic!("");
        }
    };

    tls.write("hello back".as_bytes()).unwrap();

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn run_client(socket_fd: c_int) -> sgx_status_t {
    // let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);
    //
    // // Generate Keypair
    // let ecc_handle = SgxEccHandle::new();
    // ecc_handle.open().unwrap();
    // let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();
    //
    // let (attn_report, sig, cert_ca, cert) = match create_attestation_report(&pub_k, sign_type) {
    //     Ok(r) => r,
    //     Err(e) => {
    //         println!("Error in create_attestation_report: {:?}", e);
    //         return e;
    //     }
    // };
    //
    // // let payload = attn_report + "|" + &sig + "|" + &cert;
    // let payloads = [attn_report, sig, cert_ca, cert];
    //
    // let (key_der, cert_der) = match cert::gen_ecc_cert(&payloads, &prv_k, &pub_k, &ecc_handle) {
    //     Ok(r) => r,
    //     Err(e) => {
    //         println!("Error in gen_ecc_cert: {:?}", e);
    //         return e;
    //     }
    // };
    // ecc_handle.close().unwrap();
    //
    //
    // let mut cfg = rustls::ClientConfig::new();
    // let mut certs = Vec::new();
    // certs.push(rustls::Certificate(cert_der));
    // let privkey = rustls::PrivateKey(key_der);
    //
    // cfg.set_single_client_cert(certs, privkey);
    // cfg.dangerous().set_certificate_verifier(Arc::new(ServerAuth::new(true)));
    // cfg.versions.clear();
    // cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);
    //
    // let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    // let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
    // let mut conn = TcpStream::new(socket_fd).unwrap();
    //
    // let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    // tls.write("hello".as_bytes()).unwrap();
    //
    // let mut plaintext = Vec::new();
    // match tls.read_to_end(&mut plaintext) {
    //     Ok(_) => {
    //         println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
    //     }
    //     Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
    //         println!("EOF (tls)");
    //     }
    //     Err(e) => println!("Error in read_to_end: {:?}", e),
    // }

    sgx_status_t::SGX_SUCCESS
}
