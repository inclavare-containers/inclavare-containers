#[allow(unused)]
#[allow(non_camel_case_types)]
extern crate sgx_types;
extern crate sgx_urts;

mod ratls;

use ratls::ffi as ratlsffi;

use sgx_types::{
    c_void,
    c_int,
    c_long,
    time_t,
    sgx_enclave_id_t,
    sgx_status_t,
    sgx_attributes_t,
    sgx_misc_attribute_t,
    sgx_launch_token_t,
    sgx_target_info_t,
    sgx_epid_group_id_t,
    sgx_report_t,
    sgx_init_quote,
    SgxResult,
};
use sgx_urts::SgxEnclave;

use std::default::Default;
use std::os::unix::io::{IntoRawFd, AsRawFd};
use std::env;
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::str;
use std::ptr;

use libc;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

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
pub extern "C"
fn ocall_low_res_time(__nptr: *mut c_int) {
    if __nptr.is_null() {
        return;
    }
    //FIXME
    unsafe {
        *__nptr = 100;
    }
}

#[no_mangle]
pub extern "C"
fn ocall_send(sockfd: libc::c_int, buf: *const libc::c_void, len: libc::size_t, flags: libc::c_int)
              -> libc::ssize_t {
    unsafe {
        libc::send(sockfd, buf, len, flags)
    }
}

#[no_mangle]
pub extern "C"
fn ocall_recv(sockfd: libc::c_int, buf: *mut libc::c_void, len: libc::size_t, flags: libc::c_int)
              -> libc::ssize_t {
    unsafe {
        libc::recv(sockfd, buf, len, flags)
    }
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
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

#[no_mangle]
pub extern "C"
fn ocall_sgx_init_quote(ret_target_info: *mut sgx_target_info_t) -> sgx_status_t {
    println!("[UNTRUSTED] Calling ocall_sgx_init_quote");
    let mut ret_epid_group_id: sgx_epid_group_id_t = Default::default();
    unsafe { sgx_init_quote(ret_target_info, &mut ret_epid_group_id) }
}

#[no_mangle]
pub extern "C"
fn ocall_remote_attestation(report: *mut sgx_report_t,
                            opts: *mut ratlsffi::ra_tls_options,
                            attn_report: *mut ratlsffi::attestation_verification_report_t) {
    //FIXME
    ()
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

    unsafe {
        let sgxstatus = ratlsffi::ecall_my_test_print(enclave.geteid());
        panicIfEcallFailed("ecall_my_test_print", sgxstatus);
    }

    unsafe {
        let sgxstatus = ratlsffi::ecall_wolfSSL_Debugging_ON(enclave.geteid());
        panicIfEcallFailed("ecall_wolfSSL_Debugging_ON", sgxstatus);
    }

    println!("Running server(based on wolfssl)...");
    let listener = TcpListener::bind("0.0.0.0:3443").unwrap();
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                println!("new client from {:?} {}", addr, socket.as_raw_fd());

                let mut sgxstatus = ratlsffi::_status_t_SGX_SUCCESS;
                let mut retval: c_int = 0;
                let mut method: *mut ratlsffi::WOLFSSL_METHOD = ptr::null_mut();
                let mut ctx: *mut ratlsffi::WOLFSSL_CTX = ptr::null_mut();
                let mut ssl: *mut ratlsffi::WOLFSSL = ptr::null_mut();

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

                    // Init
                    println!("ecall_wolfSSL_Init start ...");
                    sgxstatus = ratlsffi::ecall_wolfSSL_Init(enclave.geteid(), &mut retval as *mut c_int);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
                        panic!("wolfssl_Init failed: sgx_status={}, retval={}", sgxstatus, retval);
                        continue;
                    }

                    println!("ecall_wolfTLSv1_2_server_method start ...");
                    sgxstatus = ratlsffi::ecall_wolfTLSv1_2_server_method(enclave.geteid(), &mut method as *mut _);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || method.is_null() {
                        panic!("ecall_wolfTLSv1_2_server_method failed: sgx_status={}, method is_null={}", sgxstatus, method.is_null());
                        continue;
                    }

                    println!("ecall_wolfSSL_CTX_new start ...");
                    sgxstatus = ratlsffi::ecall_wolfSSL_CTX_new(enclave.geteid(), &mut ctx as *mut *mut ratlsffi::WOLFSSL_CTX, method);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || ctx.is_null() {
                        panic!("ecall_wolfSSL_CTX_new failed: sgx_status={}, ctx is_null={}", sgxstatus, ctx.is_null());
                        continue;
                    }

                    println!("ecall_create_key_and_x509 start ...");
                    sgxstatus = ratlsffi::ecall_create_key_and_x509(enclave.geteid(), ctx);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS {
                        panic!("ecall_create_key_and_x509 failed: sgx_status={}", sgxstatus);
                        continue;
                    }

                    println!("ecall_wolfSSL_new start ...");
                    sgxstatus = ratlsffi::ecall_wolfSSL_new(enclave.geteid(), &mut ssl as *mut _, ctx);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || ssl.is_null() {
                        panic!("ecall_wolfSSL_new failed: sgx_status={}, ssl is_null={}", sgxstatus, ssl.is_null());
                        continue;
                    }

                    println!("ecall_wolfSSL_set_fd start ...");
                    sgxstatus = ratlsffi::ecall_wolfSSL_set_fd(enclave.geteid(), &mut retval as *mut c_int, ssl, socket.as_raw_fd());
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
                        panic!("ecall_wolfSSL_set_fd failed: sgx_status={}, retval={}", sgxstatus, retval);
                        continue;
                    }

                    println!("ecall_wolfSSL_read start ...");
                    let mut buff: &mut [u8; 256] = &mut [0; 256];
                    sgxstatus = ratlsffi::ecall_wolfSSL_read(enclave.geteid(), &mut retval, ssl, buff.as_mut_ptr() as *mut _ as *mut c_void, 256 - 1); //TODO: 256?
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
                        if retval == ratlsffi::WOLFSSL_FATAL_ERROR {
                            ratlsffi::ecall_wolfSSL_get_error(enclave.geteid(), &mut retval as *mut _, ssl, retval);
                        }
                        panic!("ecall_wolfSSL_read failed: sgx_status={}, retval={}", sgxstatus, retval);
                        continue;
                    }

                    println!("ecall_wolfSSL_write start ...");
                    let msg = b"Hello, inclavares!\n";
                    sgxstatus = ratlsffi::ecall_wolfSSL_write(enclave.geteid(), &mut retval, ssl, msg.as_ptr() as *const _ as *const c_void, msg.len() as c_int);
                    if sgxstatus != ratlsffi::_status_t_SGX_SUCCESS || retval != ratlsffi::WOLFSSL_SUCCESS {
                        if retval == ratlsffi::WOLFSSL_FATAL_ERROR {
                            ratlsffi::ecall_wolfSSL_get_error(enclave.geteid(), &mut retval as *mut _, ssl, retval);
                        }
                        panic!("ecall_wolfSSL_write failed: sgx_status={}, retval={}", sgxstatus, retval);
                        continue;
                    }

                    if !ctx.is_null() {
                        println!("ecall_wolfSSL_CTX_free start ...");
                        ratlsffi::ecall_wolfSSL_CTX_free(enclave.geteid(), ctx);
                    }

                    if !ssl.is_null() {
                        println!("ecall_wolfSSL_free start ...");
                        ratlsffi::ecall_wolfSSL_free(enclave.geteid(), ssl);
                    }

                    println!("ecall_wolfSSL_Cleanup start ...");
                    ratlsffi::ecall_wolfSSL_Cleanup(enclave.geteid(), &mut retval as *mut _);
                    println!("ecall_wolfSSL_Cleanup: sgx_status={}, retval={}", sgxstatus, retval);
                }
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    } //loop

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


