use sgx_trts::trts::rsgx_abort;
use sgx_tstd::{
    env,
    ffi::{CStr, CString},
    mem::transmute_copy,
    mem::{size_of, size_of_val},
    os::unix::ffi::OsStrExt,
    slice::from_raw_parts,
};
use sgx_types::{
    c_char, c_int, c_long, c_uchar, c_uint, c_void, sgx_is_within_enclave, sgx_status_t, size_t,
    ssize_t, time_t,
};
use std::ffi::OsString;
use std::ptr::slice_from_raw_parts;

use crate::ratls::ffi as ratlsffi;
use crate::ratls::ffi::sgx_spid_t;
use crate::ratls::hex;

extern "C" {
    pub fn ocall_low_res_time(t: *mut c_int) -> sgx_status_t;
    pub fn ocall_send(
        sz: *mut ssize_t,
        sockfd: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
    ) -> sgx_status_t;
    pub fn ocall_recv(
        sz: *mut ssize_t,
        sockfd: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
    ) -> sgx_status_t;
}

// Link to libsgx_ra_tls_wolfssl.a
extern "C" {
    #[cfg(feature = "RATLS_EPID")]
    pub fn create_key_and_x509(
        der_key: *mut c_uchar,
        der_key_len: *mut c_uint,
        der_cert: *mut c_uchar,
        der_cert_len: *mut c_uint,
        opt: *mut ratlsffi::ra_tls_options,
    );
    #[cfg(feature = "RATLS_ECDSA")]
    pub fn ecdsa_create_key_and_x509(
        der_key: *mut c_uchar,
        der_key_len: *mut c_uint,
        der_cert: *mut c_uchar,
        der_cert_len: *mut c_uint
    );
    #[cfg(feature = "LA_REPORT")]
    pub fn la_create_key_and_x509(
        der_key: *mut c_uchar,
        der_key_len: *mut c_uint,
        der_cert: *mut c_uchar,
        der_cert_len: *mut c_uint
    );
}

#[no_mangle]
pub extern "C" fn LowResTimer() -> c_int {
    unsafe {
        let mut t: c_int = 0;
        ocall_low_res_time(&mut t as *mut c_int);
        t
    }
}

#[no_mangle]
pub extern "C" fn send(sockfd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe {
        let mut sz: ssize_t = 0;
        ocall_send(&mut sz as *mut ssize_t, sockfd, buf, len, flags);
        sz
    }
}

#[no_mangle]
pub extern "C" fn recv(sockfd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe {
        let mut sz: ssize_t = 0;
        ocall_recv(&mut sz as *mut ssize_t, sockfd, buf, len, flags);
        sz
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_Debugging_ON() {
    unsafe {
        ratlsffi::wolfSSL_Debugging_ON();
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_Debugging_OFF() {
    unsafe {
        ratlsffi::wolfSSL_Debugging_OFF();
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_Init() -> c_int {
    println!("[StubEnclave] wolfSSL_Init");
    unsafe { ratlsffi::wolfSSL_Init() }
}

#[no_mangle]
pub extern "C" fn ecall_wolfTLSv1_2_client_method() -> *mut ratlsffi::WOLFSSL_METHOD {
    unsafe { ratlsffi::wolfTLSv1_2_client_method() }
}

#[no_mangle]
pub extern "C" fn ecall_wolfTLSv1_2_server_method() -> *mut ratlsffi::WOLFSSL_METHOD {
    unsafe { ratlsffi::wolfTLSv1_2_server_method() }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_new(
    method: *mut ratlsffi::WOLFSSL_METHOD,
) -> *mut ratlsffi::WOLFSSL_CTX {
    unsafe {
        if sgx_is_within_enclave(
            method as *mut _ as *const c_void,
            ratlsffi::wolfSSL_METHOD_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_new(method)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_use_certificate_chain_buffer_format(
    ctx: *mut ratlsffi::WOLFSSL_CTX,
    buf: *const c_uchar,
    size: c_long,
    tye: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, size, tye)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_use_certificate_buffer(
    ctx: *mut ratlsffi::WOLFSSL_CTX,
    buf: *const c_uchar,
    size: c_long,
    tye: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_use_certificate_buffer(ctx, buf, size, tye)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_use_PrivateKey_buffer(
    ctx: *mut ratlsffi::WOLFSSL_CTX,
    buf: *const c_uchar,
    size: c_long,
    tye: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, size, tye)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_load_verify_buffer(
    ctx: *mut ratlsffi::WOLFSSL_CTX,
    buf: *const c_uchar,
    size: c_long,
    tye: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_load_verify_buffer(ctx, buf, size, tye)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_set_cipher_list(
    ctx: *mut ratlsffi::WOLFSSL_CTX,
    list: *const c_char,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_set_cipher_list(ctx, list)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_new(ctx: *mut ratlsffi::WOLFSSL_CTX) -> *mut ratlsffi::WOLFSSL {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_new(ctx)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_set_fd(ssl: *mut ratlsffi::WOLFSSL, fd: c_int) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_set_fd(ssl, fd)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_connect(ssl: *mut ratlsffi::WOLFSSL) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_connect(ssl)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_write(
    ssl: *mut ratlsffi::WOLFSSL,
    src: *const c_void,
    sz: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_write(ssl, src, sz)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_get_error(ssl: *mut ratlsffi::WOLFSSL, ret: c_int) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_get_error(ssl, ret)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_read(
    ssl: *mut ratlsffi::WOLFSSL,
    dst: *mut c_void,
    sz: c_int,
) -> c_int {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_read(ssl, dst, sz)
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_free(ssl: *mut ratlsffi::WOLFSSL) {
    unsafe {
        if sgx_is_within_enclave(
            ssl as *mut _ as *const c_void,
            ratlsffi::wolfSSL_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_free(ssl);
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_CTX_free(ctx: *mut ratlsffi::WOLFSSL_CTX) {
    unsafe {
        if sgx_is_within_enclave(
            ctx as *mut _ as *const c_void,
            ratlsffi::wolfSSL_CTX_GetObjectSize() as size_t,
        ) != 1
        {
            rsgx_abort();
        }
        ratlsffi::wolfSSL_CTX_free(ctx);
    }
}

#[no_mangle]
pub extern "C" fn ecall_wolfSSL_Cleanup() -> c_int {
    unsafe { ratlsffi::wolfSSL_Cleanup() }
}

#[no_mangle]
pub extern "C" fn ecall_create_key_and_x509(ctx: *mut ratlsffi::WOLFSSL_CTX) {
    let mut der_key = ['\0' as c_uchar; 2048];
    let mut der_cert = ['\0' as c_uchar; 8 * 1024];
    let mut der_key_len = size_of_val(&der_key);
    let mut der_cert_len = size_of_val(&der_cert);

    let mut ias_server = ['\0' as c_char; 512];
    let ias_server_str = "api.trustedservices.intel.com/sgx/dev";
    ias_server_str
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, v)| ias_server[i] = *v as ::std::os::raw::c_char);

    let mut subscription_key = ['\0' as c_char; 32];
    let subscription_key_str = match env::var_os("EPID_SUBSCRIPTION_KEY") {
        Some(t) => t,
        None => {
            println!("Error: ENV EPID_SUBSCRIPTION_KEY MUST BE SET");
            rsgx_abort();
        }
    };
    subscription_key_str
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, v)| subscription_key[i] = *v as ::std::os::raw::c_char);

    let spidstr = match env::var_os("SPID") {
        Some(t) => t,
        None => {
            println!("Error: ENV SPID MUST BE SET");
            rsgx_abort();
        }
    };
    let spid = hex::decode_spid(spidstr.to_str().unwrap());

    let mut quote_type = ratlsffi::sgx_quote_sign_type_t_SGX_UNLINKABLE_SIGNATURE; // default
    env::var_os("QUOTE_TYPE").and_then(|x| -> Option<OsString> {
        if x == "SGX_LINKABLE_SIGNATURE" {
            quote_type = ratlsffi::sgx_quote_sign_type_t_SGX_LINKABLE_SIGNATURE;
        }
        None
    });

    let mut opt = ratlsffi::ra_tls_options {
        spid: spid,
        quote_type: quote_type,
        ias_server,
        subscription_key,
    };

    unsafe {
        #[cfg(feature = "RATLS_EPID")]
        create_key_and_x509(
            der_key.as_mut_ptr(),
            &mut der_key_len as *mut _ as *mut c_uint,
            der_cert.as_mut_ptr(),
            &mut der_cert_len as *mut _ as *mut c_uint,
            &mut opt as *mut ratlsffi::ra_tls_options,
        );

        #[cfg(feature = "RATLS_ECDSA")]
        ecdsa_create_key_and_x509(
            der_key.as_mut_ptr(),
            &mut der_key_len as *mut _ as *mut c_uint,
            der_cert.as_mut_ptr(),
            &mut der_cert_len as *mut _ as *mut c_uint
        );

        #[cfg(feature = "LA_REPORT")]
        la_create_key_and_x509(
            der_key.as_mut_ptr(),
            &mut der_key_len as *mut _ as *mut c_uint,
            der_cert.as_mut_ptr(),
            &mut der_cert_len as *mut _ as *mut c_uint
        );

        let mut retval = ratlsffi::wolfSSL_CTX_use_certificate_buffer(
            ctx,
            der_cert.as_mut_ptr() as *const c_uchar,
            der_cert_len as c_long,
            ratlsffi::WOLFSSL_FILETYPE_ASN1,
        );
        if retval != ratlsffi::WOLFSSL_SUCCESS {
            println!("wolfSSL_CTX_use_certificate_buffer error code: {}", retval);
            rsgx_abort();
        }

        retval = ratlsffi::wolfSSL_CTX_use_PrivateKey_buffer(
            ctx,
            der_key.as_mut_ptr() as *const c_uchar,
            der_key_len as c_long,
            ratlsffi::WOLFSSL_FILETYPE_ASN1,
        );
        if retval != ratlsffi::WOLFSSL_SUCCESS {
            println!("wolfSSL_CTX_use_PrivateKey_buffer error code: {}", retval);
            rsgx_abort();
        }

        println!("ecall_create_key_and_x509 success");
    }
}
