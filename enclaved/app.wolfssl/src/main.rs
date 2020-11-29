extern crate httparse;
#[allow(unused)]
#[allow(non_camel_case_types)]
extern crate sgx_types;
extern crate sgx_urts;

mod ratls;

use http::header;
use ratls::ffi as ratlsffi;
use reqwest::header::HeaderMap;
use std::ffi::CStr;
use std::os::unix::net::UnixListener;

use sgx_types::{
    c_int, c_void, sgx_attributes_t, sgx_calc_quote_size, sgx_epid_group_id_t, sgx_get_quote,
    sgx_init_quote, sgx_launch_token_t, sgx_misc_attribute_t, sgx_report_t, sgx_status_t,
    sgx_target_info_t, SgxResult,
};
use sgx_urts::SgxEnclave;

use std::default::Default;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::ptr;
use std::str;

use libc;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";
const IAS_HOST: &'static str = "api.trustedservices.intel.com";
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

fn percent_decode(orig: String) -> String {
    let v: Vec<&str> = orig.split("%").collect();
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            ret.push(u8::from_str_radix(&s[0..2], 16).unwrap() as char);
            ret.push_str(&s[2..]);
        }
    }
    ret
}

fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
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
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state ?~@~S the same request can be repeated after
            some time. "
        }
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
            "X-IASReport-Signing-Certificate" => {
                cert = str::from_utf8(h.value).unwrap().to_string()
            }
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

pub fn retrieve_ias_report(sub_key: String, quote: &[u8]) -> (String, String, String) {
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

    println!("{}", resp.status());

    let resp = resp.text().unwrap();
    println!("{}", resp);

    let (attn_report, sig, cert) = parse_response_attn_report(resp.as_bytes());
    (attn_report, sig, cert)
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

    /*
    let mut ias_sock: i32 = 0;
        unsafe {
            status = get_ias_socket(&mut ias_sock as *mut i32);
            if status != sgx_status_t::SGX_SUCCESS {
                return;
            }
        }
    */

    let sub_key = unsafe { CStr::from_ptr((*opts).subscription_key.as_ptr()) };
    let sub_key = sub_key.to_owned().into_string().unwrap();
    retrieve_ias_report(sub_key, &quote[..]);
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
    let mut ssl: *mut ratlsffi::WOLFSSL = ptr::null_mut();
    let mut ctx: *mut ratlsffi::WOLFSSL_CTX = ptr::null_mut();

    /*
        unsafe {
            let sgxstatus = ratlsffi::ecall_my_test_print(enclave.geteid());
            panicIfEcallFailed("ecall_my_test_print", sgxstatus);
        }
    */
    unsafe {
        sgxstatus = ratlsffi::ecall_wolfSSL_Init(enclave.geteid(), &mut retval as *mut c_int);
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
            panic!(
                "wolfssl_Init failed: sgx_status={}, retval={}",
                sgxstatus, retval
            );
        }

        sgxstatus = ratlsffi::ecall_wolfSSL_Debugging_ON(enclave.geteid());
        panicIfEcallFailed("ecall_wolfSSL_Debugging_ON", sgxstatus);

        let mut method: *mut ratlsffi::WOLFSSL_METHOD = ptr::null_mut();
        sgxstatus =
            ratlsffi::ecall_wolfTLSv1_2_server_method(enclave.geteid(), &mut method as *mut _);
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

        sgxstatus = ratlsffi::ecall_wolfSSL_new(enclave.geteid(), &mut ssl as *mut _, ctx);
        if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || ssl.is_null() {
            panic!(
                "ecall_wolfSSL_new failed: sgx_status={}, ssl is_null={}",
                sgxstatus,
                ssl.is_null()
            );
        }
    }

    println!("Running server(based on wolfssl)...");
    let sock_path = "/run/rune/ra-tls.sock";
    let listener = UnixListener::bind(sock_path).unwrap();
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                println!("new client from {:?} {}", addr, socket.as_raw_fd());

                // defer! {
                //     if !ctx.is_null() {
                //         println!("ecall_wolfSSL_CTX_free start ...");
                //         unsafe { ratlsffi::ecall_wolfSSL_CTX_free(enclave.geteid(), ctx) };
                //     }
                //
                //     if !ssl.is_null() {
                //         println!("ecall_wolfSSL_free start ...");
                //         unsafe { ratlsffi::ecall_wolfSSL_free(enclave.geteid(), ssl) };
                //     }
                //
                //     println!("ecall_wolfSSL_Cleanup start ...");
                //     unsafe { ratlsffi::ecall_wolfSSL_Cleanup(enclave.geteid(), &mut retval as *mut _) };
                // }
                // ;

                unsafe {
                    println!("ecall_wolfSSL_set_fd start ...");
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

                    println!("ecall_wolfSSL_read start ...");
                    let mut buff: &mut [u8; 256] = &mut [0; 256];
                    sgxstatus = ratlsffi::ecall_wolfSSL_read(
                        enclave.geteid(),
                        &mut retval,
                        ssl,
                        buff.as_mut_ptr() as *mut _ as *mut c_void,
                        256 - 1,
                    ); //TODO: 256?
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval <= 0 {
                        if retval <= 0 {
                            ratlsffi::ecall_wolfSSL_get_error(
                                enclave.geteid(),
                                &mut retval as *mut _,
                                ssl,
                                retval,
                            );
                        }
                        panic!(
                            "ecall_wolfSSL_read failed: sgx_status={}, retval={}",
                            sgxstatus, retval
                        );
                        continue;
                    }

                    println!("ecall_wolfSSL_write start ...");
                    let msg = b"Hello, inclavares!\n";
                    sgxstatus = ratlsffi::ecall_wolfSSL_write(
                        enclave.geteid(),
                        &mut retval,
                        ssl,
                        msg.as_ptr() as *const _ as *const c_void,
                        msg.len() as c_int,
                    );
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS
                        || retval != ratlsffi::WOLFSSL_SUCCESS
                    {
                        if retval == ratlsffi::WOLFSSL_FATAL_ERROR {
                            ratlsffi::ecall_wolfSSL_get_error(
                                enclave.geteid(),
                                &mut retval as *mut _,
                                ssl,
                                retval,
                            );
                        }
                        panic!(
                            "ecall_wolfSSL_write failed: sgx_status={}, retval={}",
                            sgxstatus, retval
                        );
                        continue;
                    }

                    // FIXME: close the client connection
                }
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } //loop

    unsafe {
        if !ctx.is_null() {
            ratlsffi::ecall_wolfSSL_CTX_free(enclave.geteid(), ctx);
        }

        if !ssl.is_null() {
            ratlsffi::ecall_wolfSSL_free(enclave.geteid(), ssl);
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
