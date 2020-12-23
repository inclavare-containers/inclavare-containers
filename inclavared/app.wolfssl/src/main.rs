#[allow(unused)]
#[allow(non_camel_case_types)]
mod ratls;

use http::header;
use http::StatusCode;
use libc;
use ratls::ffi as ratlsffi;
use reqwest::header::HeaderMap;
use sgx_types::{
    c_int, c_void, sgx_attributes_t, sgx_calc_quote_size, sgx_epid_group_id_t, sgx_get_quote,
    sgx_init_quote, sgx_launch_token_t, sgx_misc_attribute_t, sgx_report_t, sgx_status_t,
    sgx_target_info_t, SgxResult,
};
use sgx_urts::SgxEnclave;
use std::default::Default;
use std::ffi::CStr;
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::ptr;
use std::str;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
const IAS_REPORT_API_URL: &'static str =
    "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report";

// ECall function format:
//   fn my_func(sgx_enclaved_id_t, retval, param1, param2, ...) -> sgx_status_t

// extern {
//     fn ecall_wolfSSL_Init(eid: sgx_enclave_id_t, retval: *mut c_int)
//                           -> sgx_status_t;
//
//     fn ecall_wolfTLSv1_2_server_method(eid: sgx_enclave_id_t, retval: *mut ratlsffi::WOLFSSL_METHOD)
//                                        -> sgx_status_t;
//
//     fn ecall_wolfSSL_CTX_new(eid: sgx_enclave_id_t, retval: *mut ratlsffi::WOLFSSL_CTX,
//                              method: *mut ratlsffi::WOLFSSL_METHOD) -> sgx_status_t;
//
//     fn ecall_create_key_and_x509(eid: sgx_enclave_id_t, ctx: *mut ratlsffi::WOLFSSL_CTX)
//         -> sgx_status_t;
//
//     fn ecall_wolfSSL_new(eid: sgx_enclave_id_t, retval: *mut ratlsffi::WOLFSSL, ctx: *mut ratlsffi::WOLFSSL_CTX)
//         -> sgx_status_t;
//
//     fn ecall_wolfSSL_set_fd(eid: sgx_enclave_id_t, retval: *mut c_int,
//                             ssl: *mut ratlsffi::WOLFSSL, fd: c_int);
//
//     fn ecall_wolfSSL_read(eid: sgx_enclave_id_t, retval: *const c_int,
//                           ssl: *mut ratlsffi::WOLFSSL, dst: *mut c_void, sz: c_int) -> c_int;
//
//     fn ecall_wolfSSL_write(eid: sgx_enclave_id_t, retval: *const c_int,
//                            ssl: *mut ratlsffi::WOLFSSL, src: *const c_void, sz: c_int) -> c_int;
//
//     fn ecall_wolfSSL_free(eid: sgx_enclave_id_t, retval: *mut c_int,
//                           ssl: *mut ratlsffi::WOLFSSL);
//
//     fn ecall_wolfSSL_CTX_free(eid: sgx_enclave_id_t, retval: *mut c_int,
//                               ctx: *mut ratlsffi::WOLFSSL_CTX);
//
//     fn ecall_wolfSSL_Cleanup(eid: sgx_enclave_id_t, retval: *mut c_int) -> c_int;
//
//     fn ecall_wolfSSL_Debugging_ON(eid: sgx_enclave_id_t);
// }

// pub type __time_t = c_long;
// pub type __suseconds_t = c_long;
//
// #[repr(C)]
// #[derive(Debug, Copy, Clone, Default)]
// pub struct timeval {
//     pub tv_sec: __time_t,
//     pub tv_usec: __suseconds_t,
// }

#[no_mangle]
pub extern "C" fn ocall_low_res_time(__nptr: *mut c_int) {
    if __nptr.is_null() {
        return;
    }
    //FIXME
    unsafe {
        *__nptr = 100;
    }
}

#[no_mangle]
pub extern "C" fn ocall_send(
    sockfd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    unsafe { libc::send(sockfd, buf, len, flags) }
}

#[no_mangle]
pub extern "C" fn ocall_recv(
    sockfd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    unsafe { libc::recv(sockfd, buf, len, flags) }
}

////FIXME: remove XTIME
//#[no_mangle]
//pub extern "C"
//fn ocall_XTIME(t: *mut libc::time_t) -> libc::time_t {
//    //FIXME
//    let x: time_t = 1512498557;
//    if !t.is_null() {
//        unsafe { *t = x; }
//    }
//    x
//}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(ret_target_info: *mut sgx_target_info_t) -> sgx_status_t {
    println!("[UNTRUSTED] Calling ocall_sgx_init_quote");
    let mut ret_epid_group_id: sgx_epid_group_id_t = Default::default();
    unsafe { sgx_init_quote(ret_target_info, &mut ret_epid_group_id) }
}

fn parse_response_attn_report(
    resp: reqwest::blocking::Response,
    attn_report: *mut ratlsffi::attestation_verification_report_t,
) {
    let resp_headers = resp.headers();
    for (k, v) in resp_headers.iter() {
        println!("{:?}: {:?}", k, v);
    }

    let mut cert = resp_headers
        .get("X-IASReport-Signing-Certificate")
        .unwrap()
        .as_bytes();
    let cert = percent_encoding::percent_decode(cert)
        .decode_utf8()
        .unwrap();

    let pem_head = "-----BEGIN CERTIFICATE-----";
    let pem_head_len = pem_head.len();
    let v: Vec<&str> = cert.split(pem_head).collect();
    let sign_cert = v[1].as_bytes();
    let sign_cert_len = pem_head_len + sign_cert.len();
    unsafe {
        (*attn_report).ias_sign_cert[..pem_head_len].clone_from_slice(&pem_head.as_bytes());
        (*attn_report).ias_sign_cert[pem_head_len..sign_cert_len].clone_from_slice(&sign_cert);
        (*attn_report).ias_sign_cert_len = sign_cert_len as u32;
        println!(
            "sign cert({}) {}",
            sign_cert_len - 1,
            str::from_utf8(&((*attn_report).ias_sign_cert)[..sign_cert_len - 1]).unwrap()
        );
    }

    let sign_ca_cert = v[2].as_bytes();
    let sign_ca_cert_len = pem_head_len + sign_ca_cert.len();
    unsafe {
        (*attn_report).ias_sign_ca_cert[..pem_head_len].clone_from_slice(&pem_head.as_bytes());
        (*attn_report).ias_sign_ca_cert[pem_head_len..sign_ca_cert_len]
            .clone_from_slice(&sign_ca_cert);
        (*attn_report).ias_sign_ca_cert_len = sign_ca_cert_len as u32;
        println!(
            "sign ca cert({}) {}",
            sign_ca_cert_len - 1,
            str::from_utf8(&((*attn_report).ias_sign_ca_cert)[..sign_ca_cert_len - 1]).unwrap()
        );
    }

    let sig = resp_headers
        .get("X-IASReport-Signature")
        .unwrap()
        .as_bytes();
    let sig_len = sig.len();
    unsafe {
        (*attn_report).ias_report_signature[..sig_len].clone_from_slice(&sig);
        (*attn_report).ias_report_signature_len = sig_len as u32;
        println!(
            "report signature({}) {}",
            sig_len,
            std::str::from_utf8(&((*attn_report).ias_report_signature)[..sig_len]).unwrap()
        );
    }

    let report_len = resp.content_length().unwrap() as usize;
    unsafe {
        (*attn_report).ias_report_len = report_len as u32;
    }

    let report = resp.bytes().unwrap();
    unsafe {
        (*attn_report).ias_report[..report_len].clone_from_slice(&report.slice(..));
        println!(
            "report({}) {}",
            report_len - 1,
            std::str::from_utf8(&((*attn_report).ias_report)[..report_len - 1]).unwrap()
        );
    }
}

pub fn retrieve_ias_report(
    sub_key: String,
    quote: &[u8],
    attn_report: *mut ratlsffi::attestation_verification_report_t,
) {
    // The common headers like Host, Content-length, Connection, Agent
    // are all not required.
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert("Ocp-Apim-Subscription-Key", sub_key.parse().unwrap());

    // FIXME: support Nonce and PseManifest
    let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", base64::encode(quote));

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(IAS_REPORT_API_URL)
        .headers(headers)
        .body(body)
        .send()
        .unwrap();

    let msg: String = match resp.status() {
        StatusCode::OK => "200 OK: Operation Successful".to_string(),
        StatusCode::BAD_REQUEST => {
            "400 Bad Request: Invalid Attestation Evidence Payload".to_string()
        }
        StatusCode::UNAUTHORIZED => {
            "401 Unauthorized: Failed to authenticate or authorize request".to_string()
        }
        StatusCode::NOT_FOUND => {
            "404 Not Found: GID does not refer to a valid EPID group ID".to_string()
        }
        StatusCode::INTERNAL_SERVER_ERROR => "500 Internal error occurred".to_string(),
        StatusCode::SERVICE_UNAVAILABLE => {
            "503 Service Unavailable: Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state - the same request can be repeated after
            some time"
                .to_string()
        }
        _ => format!("{}: Unknown error occured", resp.status()),
    };
    println!("{}", msg);

    if resp.status() != StatusCode::OK {
        return;
    }

    parse_response_attn_report(resp, attn_report);
}

#[no_mangle]
pub extern "C" fn ocall_remote_attestation(
    report: *mut sgx_report_t,
    opts: *mut ratlsffi::ra_tls_options,
    attn_report: *mut ratlsffi::attestation_verification_report_t,
) {
    let quote_type = unsafe { (*opts).quote_type };
    let quote_type = if quote_type == ratlsffi::sgx_quote_sign_type_t_SGX_UNLINKABLE_SIGNATURE {
        sgx_types::sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE
    } else if quote_type == ratlsffi::sgx_quote_sign_type_t_SGX_LINKABLE_SIGNATURE {
        sgx_types::sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE
    } else {
        println!("unknown quote type {}", quote_type as u32);
        return;
    };

    let mut quote_size: u32 = 0;
    let mut status =
        unsafe { sgx_calc_quote_size(ptr::null_mut(), 0, &mut quote_size as *mut u32) };

    if status != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", status);
        return;
    }

    let mut quote: Vec<u8> = vec![0u8; quote_size as usize];
    let c_quote = quote.as_mut_ptr() as *mut u8;

    let mut spid = sgx_types::sgx_spid_t::default();
    unsafe {
        spid.id.copy_from_slice(&(*opts).spid.id);
    }

    status = unsafe {
        sgx_get_quote(
            report,
            quote_type,
            &spid as *const sgx_types::sgx_spid_t,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            c_quote as *mut sgx_types::sgx_quote_t,
            quote_size,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", status);
        return;
    }

    let sub_key = unsafe { CStr::from_ptr((*opts).subscription_key.as_ptr()) };
    let sub_key = sub_key.to_owned().into_string().unwrap();
    retrieve_ias_report(sub_key, &quote[..], attn_report);
}

// struct ScopeCall<F: FnMut()> {
//     c: F
// }
// impl<F: FnMut()> Drop for ScopeCall<F> {
//     fn drop(&mut self) {
//         (self.c)();
//     }
// }
//
// macro_rules! expr {
//     ($e: expr) => { $e }
// }
// macro_rules! defer {
//     ($($data: tt)*) => (
//         let _scope_call = ScopeCall {
//             c: || -> () { expr!({ $($data)* }) }
//         };
//     )
// }

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let mut sgxstatus = ratlsffi::_status_t_SGX_SUCCESS;
    let mut retval: c_int = 0;
    let mut ctx: *mut ratlsffi::WOLFSSL_CTX = ptr::null_mut();

    unsafe {
        sgxstatus = ratlsffi::ecall_wolfSSL_Debugging_ON(enclave.geteid());
        panicIfEcallFailed("ecall_wolfSSL_Debugging_ON", sgxstatus);

        sgxstatus = ratlsffi::ecall_wolfSSL_Init(enclave.geteid(), &mut retval as *mut c_int);
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
            panic!(
                "wolfssl_Init failed: sgx_status={}, retval={}",
                sgxstatus, retval
            );
        }

        let mut method: *mut ratlsffi::WOLFSSL_METHOD = ptr::null_mut();
        sgxstatus =
            ratlsffi::ecall_wolfTLSv1_2_server_method(enclave.geteid(), &mut method as *mut *mut _);
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || method.is_null() {
            panic!(
                "ecall_wolfTLSv1_2_server_method failed: sgx_status={}, method is_null={}",
                sgxstatus,
                method.is_null()
            );
        }

        sgxstatus = ratlsffi::ecall_wolfSSL_CTX_new(
            enclave.geteid(),
            &mut ctx as *mut *mut ratlsffi::WOLFSSL_CTX,
            method,
        );
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || ctx.is_null() {
            panic!(
                "ecall_wolfSSL_CTX_new failed: sgx_status={}, ctx is_null={}",
                sgxstatus,
                ctx.is_null()
            );
        }

        sgxstatus = ratlsffi::ecall_create_key_and_x509(enclave.geteid(), ctx);
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS {
            panic!("ecall_create_key_and_x509 failed: sgx_status={}", sgxstatus);
        }
    }

    println!("Running server(based on wolfssl)...");

    let sock_path = "/run/rune/ra-tls.sock";
    let _ = std::fs::remove_file(sock_path);

    let listener = UnixListener::bind(sock_path).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                println!("new client from {:?} {}", addr, socket.as_raw_fd());

                unsafe {
                    let mut ssl: *mut ratlsffi::WOLFSSL = ptr::null_mut();

                    sgxstatus =
                        ratlsffi::ecall_wolfSSL_new(enclave.geteid(), &mut ssl as *mut *mut _, ctx);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || ssl.is_null() {
                        panic!(
                            "ecall_wolfSSL_new failed: sgx_status={}, ssl is_null={}",
                            sgxstatus,
                            ssl.is_null()
                        );
                    }

                    sgxstatus = ratlsffi::ecall_wolfSSL_set_fd(
                        enclave.geteid(),
                        &mut retval as *mut c_int,
                        ssl,
                        socket.as_raw_fd(),
                    );
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS
                        || retval != ratlsffi::WOLFSSL_SUCCESS
                    {
                        panic!(
                            "ecall_wolfSSL_set_fd failed: sgx_status={}, retval={}",
                            sgxstatus, retval
                        );
                        continue;
                    }

                    let mut buff: [u8; 256] = [0; 256];
                    sgxstatus = ratlsffi::ecall_wolfSSL_read(
                        enclave.geteid(),
                        &mut retval as *mut c_int,
                        ssl,
                        buff.as_mut_ptr() as *mut c_void,
                        256 - 1,
                    ); //TODO: 256?
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval <= 0 {
                        if retval == ratlsffi::WOLFSSL_FATAL_ERROR {
                            ratlsffi::ecall_wolfSSL_get_error(
                                enclave.geteid(),
                                &mut retval as *mut _,
                                ssl,
                                retval,
                            );
                        }

                        println!(
                            "ecall_wolfSSL_read failed: sgx_status={}, retval={}",
                            sgxstatus, retval
                        );
                        ratlsffi::ecall_wolfSSL_free(enclave.geteid(), ssl);
                        continue;
                    }

                    let msg = "Hello, Inclavare Containers!\n";
                    sgxstatus = ratlsffi::ecall_wolfSSL_write(
                        enclave.geteid(),
                        &mut retval,
                        ssl,
                        msg.as_ptr() as *const c_void,
                        msg.len() as c_int,
                    );
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval <= 0 {
                        if retval == ratlsffi::WOLFSSL_FATAL_ERROR {
                            ratlsffi::ecall_wolfSSL_get_error(
                                enclave.geteid(),
                                &mut retval as *mut _,
                                ssl,
                                retval,
                            );
                        }
                        println!(
                            "ecall_wolfSSL_write failed: sgx_status={}, retval={}",
                            sgxstatus, retval
                        );
                    }

                    ratlsffi::ecall_wolfSSL_free(enclave.geteid(), ssl);
                }

                socket.shutdown(Shutdown::Both).expect("shutdown failed");
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }

    unsafe {
        if !ctx.is_null() {
            ratlsffi::ecall_wolfSSL_CTX_free(enclave.geteid(), ctx);
        }

        ratlsffi::ecall_wolfSSL_Cleanup(enclave.geteid(), &mut retval as *mut _);
    }

    println!("Destroying enclave ...");

    enclave.destroy();
}

fn panicIfFailed(prefix: &str, retval: c_int) {
    if retval != ratlsffi::WOLFSSL_SUCCESS {
        panic!("{} {:?}", prefix, retval);
    }
}

fn panicIfEcallFailed(prefix: &str, code: ratlsffi::sgx_status_t) {
    if code != ratlsffi::_status_t_SGX_SUCCESS {
        panic!("{} {:?}", prefix, code);
    }
}
