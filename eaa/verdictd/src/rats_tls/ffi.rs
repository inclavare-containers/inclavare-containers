/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pub const ERR_CODE_CLASS_SHIFT: u32 = 28;
pub const ERR_CODE_SUBCLASS_SHIFT: u32 = 23;
pub const ERR_CODE_CLASS_MASK: u32 = 1879048192;
pub const ERR_CODE_SUBCLASS_MASK: u32 = 260046848;
pub const ERR_CODE_ERROR_MASK: u32 = 8388607;
pub const ERR_CODE_NAGATIVE: u32 = 2147483648;
pub const RATS_TLS_ERR_BASE: u32 = 0;
pub const TLS_WRAPPER_ERR_BASE: u32 = 268435456;
pub const ENCLAVE_QUOTE_ERR_BASE: u32 = 536870912;
pub const CRYPTO_WRAPPER_ERR_BASE: u32 = 805306368;
pub const SGX_ECDSA_ERR_BASE: u32 = 0;
pub const SGX_LA_ERR_BASE: u32 = 0;
pub const true_: u32 = 1;
pub const false_: u32 = 0;
pub const __bool_true_false_are_defined: u32 = 1;
pub const _STDINT_H: u32 = 1;
pub const _FEATURES_H: u32 = 1;
pub const _DEFAULT_SOURCE: u32 = 1;
pub const __USE_ISOC11: u32 = 1;
pub const __USE_ISOC99: u32 = 1;
pub const __USE_ISOC95: u32 = 1;
pub const __USE_POSIX_IMPLICITLY: u32 = 1;
pub const _POSIX_SOURCE: u32 = 1;
pub const _POSIX_C_SOURCE: u32 = 200809;
pub const __USE_POSIX: u32 = 1;
pub const __USE_POSIX2: u32 = 1;
pub const __USE_POSIX199309: u32 = 1;
pub const __USE_POSIX199506: u32 = 1;
pub const __USE_XOPEN2K: u32 = 1;
pub const __USE_XOPEN2K8: u32 = 1;
pub const _ATFILE_SOURCE: u32 = 1;
pub const __USE_MISC: u32 = 1;
pub const __USE_ATFILE: u32 = 1;
pub const __USE_FORTIFY_LEVEL: u32 = 0;
pub const _STDC_PREDEF_H: u32 = 1;
pub const __STDC_IEC_559__: u32 = 1;
pub const __STDC_IEC_559_COMPLEX__: u32 = 1;
pub const __STDC_ISO_10646__: u32 = 201605;
pub const __STDC_NO_THREADS__: u32 = 1;
pub const __GNU_LIBRARY__: u32 = 6;
pub const __GLIBC__: u32 = 2;
pub const __GLIBC_MINOR__: u32 = 24;
pub const _SYS_CDEFS_H: u32 = 1;
pub const __WORDSIZE: u32 = 64;
pub const __WORDSIZE_TIME64_COMPAT32: u32 = 1;
pub const __SYSCALL_WORDSIZE: u32 = 64;
pub const _BITS_WCHAR_H: u32 = 1;
pub const INT8_MIN: i32 = -128;
pub const INT16_MIN: i32 = -32768;
pub const INT32_MIN: i32 = -2147483648;
pub const INT8_MAX: u32 = 127;
pub const INT16_MAX: u32 = 32767;
pub const INT32_MAX: u32 = 2147483647;
pub const UINT8_MAX: u32 = 255;
pub const UINT16_MAX: u32 = 65535;
pub const UINT32_MAX: u32 = 4294967295;
pub const INT_LEAST8_MIN: i32 = -128;
pub const INT_LEAST16_MIN: i32 = -32768;
pub const INT_LEAST32_MIN: i32 = -2147483648;
pub const INT_LEAST8_MAX: u32 = 127;
pub const INT_LEAST16_MAX: u32 = 32767;
pub const INT_LEAST32_MAX: u32 = 2147483647;
pub const UINT_LEAST8_MAX: u32 = 255;
pub const UINT_LEAST16_MAX: u32 = 65535;
pub const UINT_LEAST32_MAX: u32 = 4294967295;
pub const INT_FAST8_MIN: i32 = -128;
pub const INT_FAST16_MIN: i64 = -9223372036854775808;
pub const INT_FAST32_MIN: i64 = -9223372036854775808;
pub const INT_FAST8_MAX: u32 = 127;
pub const INT_FAST16_MAX: u64 = 9223372036854775807;
pub const INT_FAST32_MAX: u64 = 9223372036854775807;
pub const UINT_FAST8_MAX: u32 = 255;
pub const UINT_FAST16_MAX: i32 = -1;
pub const UINT_FAST32_MAX: i32 = -1;
pub const INTPTR_MIN: i64 = -9223372036854775808;
pub const INTPTR_MAX: u64 = 9223372036854775807;
pub const UINTPTR_MAX: i32 = -1;
pub const PTRDIFF_MIN: i64 = -9223372036854775808;
pub const PTRDIFF_MAX: u64 = 9223372036854775807;
pub const SIG_ATOMIC_MIN: i32 = -2147483648;
pub const SIG_ATOMIC_MAX: u32 = 2147483647;
pub const SIZE_MAX: i32 = -1;
pub const WINT_MIN: u32 = 0;
pub const WINT_MAX: u32 = 4294967295;
pub const TLS_TYPE_NAME_SIZE: u32 = 32;
pub const QUOTE_TYPE_NAME_SIZE: u32 = 32;
pub const CRYPTO_TYPE_NAME_SIZE: u32 = 32;
pub const ENCLAVE_SGX_SPID_LENGTH: u32 = 16;
pub const SHA256_HASH_SIZE: u32 = 32;
pub const RATS_TLS_API_VERSION_1: u32 = 1;
pub const RATS_TLS_API_VERSION_MAX: u32 = 1;
pub const RATS_TLS_API_VERSION_DEFAULT: u32 = 1;
pub const RATS_TLS_CONF_FLAGS_GLOBAL_MASK_SHIFT: u32 = 0;
pub const RATS_TLS_CONF_FLAGS_PRIVATE_MASK_SHIFT: u32 = 32;
pub const RATS_TLS_CONF_FLAGS_MUTUAL: u64 = 1;
pub const RATS_TLS_CONF_FLAGS_SERVER: u64 = 2;
pub const RATS_TLS_ERR_NONE: rats_tls_err_t = 0;
pub const RATS_TLS_ERR_UNKNOWN: rats_tls_err_t = 1;
pub const RATS_TLS_ERR_INVALID: rats_tls_err_t = 2;
pub const RATS_TLS_ERR_NO_MEM: rats_tls_err_t = 3;
pub const RATS_TLS_ERR_NOT_REGISTERED: rats_tls_err_t = 4;
pub const RATS_TLS_ERR_LOAD_CRYPTO_WRAPPERS: rats_tls_err_t = 5;
pub const RATS_TLS_ERR_LOAD_TLS_WRAPPERS: rats_tls_err_t = 6;
pub const RATS_TLS_ERR_LOAD_ENCLAVE_QUOTES: rats_tls_err_t = 7;
pub const RATS_TLS_ERR_DLOPEN: rats_tls_err_t = 8;
pub const RATS_TLS_ERR_INIT: rats_tls_err_t = 9;
pub const RATS_TLS_ERR_UNSUPPORTED_CERT_ALGO: rats_tls_err_t = 10;
pub type rats_tls_err_t = ::std::os::raw::c_uint;
pub const ENCLAVE_QUOTE_ERR_NONE: enclave_quote_err_t = 536870912;
pub const ENCLAVE_QUOTE_ERR_UNKNOWN: enclave_quote_err_t = 536870913;
pub const ENCLAVE_QUOTE_ERR_NO_MEM: enclave_quote_err_t = 536870914;
pub const ENCLAVE_QUOTE_ERR_INVALID: enclave_quote_err_t = 536870915;
pub type enclave_quote_err_t = ::std::os::raw::c_uint;
pub const TLS_WRAPPER_ERR_NONE: tls_wrapper_err_t = 268435456;
pub const TLS_WRAPPER_ERR_NO_MEM: tls_wrapper_err_t = 268435457;
pub const TLS_WRAPPER_ERR_NOT_FOUND: tls_wrapper_err_t = 268435458;
pub const TLS_WRAPPER_ERR_INVALID: tls_wrapper_err_t = 268435459;
pub const TLS_WRAPPER_ERR_TRANSMIT: tls_wrapper_err_t = 268435460;
pub const TLS_WRAPPER_ERR_RECEIVE: tls_wrapper_err_t = 268435461;
pub const TLS_WRAPPER_ERR_UNSUPPORTED_QUOTE: tls_wrapper_err_t = 268435462;
pub const TLS_WRAPPER_ERR_PRIV_KEY: tls_wrapper_err_t = 268435463;
pub const TLS_WRAPPER_ERR_CERT: tls_wrapper_err_t = 268435464;
pub const TLS_WRAPPER_ERR_UNKNOWN: tls_wrapper_err_t = 268435465;
pub type tls_wrapper_err_t = ::std::os::raw::c_uint;
pub const CRYPTO_WRAPPER_ERR_NONE: crypto_wrapper_err_t = 805306368;
pub const CRYPTO_WRAPPER_ERR_NO_MEM: crypto_wrapper_err_t = 805306369;
pub const CRYPTO_WRAPPER_ERR_INVALID: crypto_wrapper_err_t = 805306370;
pub const CRYPTO_WRAPPER_ERR_CERT: crypto_wrapper_err_t = 805306371;
pub const CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN: crypto_wrapper_err_t = 805306372;
pub const CRYPTO_WRAPPER_ERR_RSA_KEY_LEN: crypto_wrapper_err_t = 805306373;
pub const CRYPTO_WRAPPER_ERR_PUB_KEY_LEN: crypto_wrapper_err_t = 805306374;
pub const CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO: crypto_wrapper_err_t = 805306375;
pub const CRYPTO_WRAPPER_ERR_PUB_KEY_DECODE: crypto_wrapper_err_t = 805306376;
pub type crypto_wrapper_err_t = ::std::os::raw::c_uint;
pub type int_least8_t = ::std::os::raw::c_schar;
pub type int_least16_t = ::std::os::raw::c_short;
pub type int_least32_t = ::std::os::raw::c_int;
pub type int_least64_t = ::std::os::raw::c_long;
pub type uint_least8_t = ::std::os::raw::c_uchar;
pub type uint_least16_t = ::std::os::raw::c_ushort;
pub type uint_least32_t = ::std::os::raw::c_uint;
pub type uint_least64_t = ::std::os::raw::c_ulong;
pub type int_fast8_t = ::std::os::raw::c_schar;
pub type int_fast16_t = ::std::os::raw::c_long;
pub type int_fast32_t = ::std::os::raw::c_long;
pub type int_fast64_t = ::std::os::raw::c_long;
pub type uint_fast8_t = ::std::os::raw::c_uchar;
pub type uint_fast16_t = ::std::os::raw::c_ulong;
pub type uint_fast32_t = ::std::os::raw::c_ulong;
pub type uint_fast64_t = ::std::os::raw::c_ulong;
pub type intmax_t = ::std::os::raw::c_long;
pub type uintmax_t = ::std::os::raw::c_ulong;
pub type size_t = ::std::os::raw::c_ulong;
pub type wchar_t = ::std::os::raw::c_int;
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Default, Copy, Clone)]
pub struct max_align_t {
    pub __clang_max_align_nonce1: ::std::os::raw::c_longlong,
    pub __bindgen_padding_0: u64,
    pub __clang_max_align_nonce2: u128,
}
#[test]
fn bindgen_test_layout_max_align_t() {
    assert_eq!(
        ::std::mem::size_of::<max_align_t>(),
        32usize,
        concat!("Size of: ", stringify!(max_align_t))
    );
    assert_eq!(
        ::std::mem::align_of::<max_align_t>(),
        16usize,
        concat!("Alignment of ", stringify!(max_align_t))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<max_align_t>())).__clang_max_align_nonce1 as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(max_align_t),
            "::",
            stringify!(__clang_max_align_nonce1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<max_align_t>())).__clang_max_align_nonce2 as *const _ as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(max_align_t),
            "::",
            stringify!(__clang_max_align_nonce2)
        )
    );
}
pub const RATS_TLS_LOG_LEVEL_DEBUG: rats_tls_log_level_t = 0;
pub const RATS_TLS_LOG_LEVEL_INFO: rats_tls_log_level_t = 1;
pub const RATS_TLS_LOG_LEVEL_WARN: rats_tls_log_level_t = 2;
pub const RATS_TLS_LOG_LEVEL_ERROR: rats_tls_log_level_t = 3;
pub const RATS_TLS_LOG_LEVEL_FATAL: rats_tls_log_level_t = 4;
pub const RATS_TLS_LOG_LEVEL_NONE: rats_tls_log_level_t = 5;
pub const RATS_TLS_LOG_LEVEL_MAX: rats_tls_log_level_t = 6;
pub const RATS_TLS_LOG_LEVEL_DEFAULT: rats_tls_log_level_t = 3;
pub type rats_tls_log_level_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_handle {
    _unused: [u8; 0],
}
pub const RATS_TLS_CERT_ALGO_RSA_3072_SHA256: rats_tls_cert_algo_t = 0;
pub const RATS_TLS_CERT_ALGO_ECC_256_SHA256: rats_tls_cert_algo_t = 1;
pub const RATS_TLS_CERT_ALGO_MAX: rats_tls_cert_algo_t = 2;
pub const RATS_TLS_CERT_ALGO_DEFAULT: rats_tls_cert_algo_t = 1;
pub type rats_tls_cert_algo_t = ::std::os::raw::c_uint;
pub const VERIFICATION_TYPE_QVL: quote_sgx_ecdsa_verification_type_t = 0;
pub const VERIFICATION_TYPE_QEL: quote_sgx_ecdsa_verification_type_t = 1;
pub type quote_sgx_ecdsa_verification_type_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_conf_t {
    pub api_version: ::std::os::raw::c_uint,
    pub flags: ::std::os::raw::c_ulong,
    pub log_level: rats_tls_log_level_t,
    pub tls_type: [::std::os::raw::c_uchar; 32usize],
    pub attester_type: [::std::os::raw::c_uchar; 32usize],
    pub verifier_type: [::std::os::raw::c_uchar; 32usize],
    pub crypto_type: [::std::os::raw::c_uchar; 32usize],
    pub cert_algo: rats_tls_cert_algo_t,
    pub enclave_id: ::std::os::raw::c_ulonglong,
    pub quote_sgx_epid: rats_tls_conf_t__bindgen_ty_1,
    pub quote_sgx_ecdsa: rats_tls_conf_t__bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct rats_tls_conf_t__bindgen_ty_1 {
    pub valid: bool,
    pub spid: [u8; 16usize],
    pub linkable: bool,
}
#[test]
fn bindgen_test_layout_rats_tls_conf_t__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<rats_tls_conf_t__bindgen_ty_1>(),
        18usize,
        concat!("Size of: ", stringify!(rats_tls_conf_t__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<rats_tls_conf_t__bindgen_ty_1>(),
        1usize,
        concat!(
            "Alignment of ",
            stringify!(rats_tls_conf_t__bindgen_ty_1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_1>())).valid as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_1),
            "::",
            stringify!(valid)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_1>())).spid as *const _ as usize
        },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_1),
            "::",
            stringify!(spid)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_1>())).linkable as *const _
                as usize
        },
        17usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_1),
            "::",
            stringify!(linkable)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_conf_t__bindgen_ty_2 {
    pub valid: bool,
    pub cert_type: u8,
    pub verification_type: quote_sgx_ecdsa_verification_type_t,
}
#[test]
fn bindgen_test_layout_rats_tls_conf_t__bindgen_ty_2() {
    assert_eq!(
        ::std::mem::size_of::<rats_tls_conf_t__bindgen_ty_2>(),
        8usize,
        concat!("Size of: ", stringify!(rats_tls_conf_t__bindgen_ty_2))
    );
    assert_eq!(
        ::std::mem::align_of::<rats_tls_conf_t__bindgen_ty_2>(),
        4usize,
        concat!(
            "Alignment of ",
            stringify!(rats_tls_conf_t__bindgen_ty_2)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_2>())).valid as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_2),
            "::",
            stringify!(valid)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_2>())).cert_type as *const _
                as usize
        },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_2),
            "::",
            stringify!(cert_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t__bindgen_ty_2>())).verification_type
                as *const _ as usize
        },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t__bindgen_ty_2),
            "::",
            stringify!(verification_type)
        )
    );
}
impl Default for rats_tls_conf_t__bindgen_ty_2 {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}
#[test]
fn bindgen_test_layout_rats_tls_conf_t() {
    assert_eq!(
        ::std::mem::size_of::<rats_tls_conf_t>(),
        192usize,
        concat!("Size of: ", stringify!(rats_tls_conf_t))
    );
    assert_eq!(
        ::std::mem::align_of::<rats_tls_conf_t>(),
        8usize,
        concat!("Alignment of ", stringify!(rats_tls_conf_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).api_version as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(api_version)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).flags as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).log_level as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(log_level)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).tls_type as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(tls_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t>())).attester_type as *const _ as usize
        },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(attester_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t>())).verifier_type as *const _ as usize
        },
        84usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(verifier_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).crypto_type as *const _ as usize },
        116usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(crypto_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).cert_algo as *const _ as usize },
        148usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(cert_algo)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rats_tls_conf_t>())).enclave_id as *const _ as usize },
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(enclave_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t>())).quote_sgx_epid as *const _ as usize
        },
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(quote_sgx_epid)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rats_tls_conf_t>())).quote_sgx_ecdsa as *const _ as usize
        },
        180usize,
        concat!(
            "Offset of field: ",
            stringify!(rats_tls_conf_t),
            "::",
            stringify!(quote_sgx_ecdsa)
        )
    );
}
impl Default for rats_tls_conf_t {
    fn default() -> Self {
        let mut conf: rats_tls_conf_t = unsafe { ::std::mem::zeroed() };
        conf.log_level = RATS_TLS_LOG_LEVEL_DEFAULT;
        conf
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtls_sgx_evidence {
    pub mr_enclave: *mut u8,
    pub mr_signer: *mut u8,
    pub product_id: u32,
    pub security_version: u32,
    pub attributes: *mut u8,
    pub collateral_size: size_t,
    pub collateral: *mut ::std::os::raw::c_char,
}
#[test]
fn bindgen_test_layout_rtls_sgx_evidence() {
    assert_eq!(
        ::std::mem::size_of::<rtls_sgx_evidence>(),
        48usize,
        concat!("Size of: ", stringify!(rtls_sgx_evidence))
    );
    assert_eq!(
        ::std::mem::align_of::<rtls_sgx_evidence>(),
        8usize,
        concat!("Alignment of ", stringify!(rtls_sgx_evidence))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_sgx_evidence>())).mr_enclave as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(mr_enclave)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_sgx_evidence>())).mr_signer as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(mr_signer)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_sgx_evidence>())).product_id as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(product_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rtls_sgx_evidence>())).security_version as *const _ as usize
        },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(security_version)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_sgx_evidence>())).attributes as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(attributes)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<rtls_sgx_evidence>())).collateral_size as *const _ as usize
        },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(collateral_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_sgx_evidence>())).collateral as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_sgx_evidence),
            "::",
            stringify!(collateral)
        )
    );
}
pub type rtls_sgx_evidence_t = rtls_sgx_evidence;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtls_tdx_evidence {}
#[test]
fn bindgen_test_layout_rtls_tdx_evidence() {
    assert_eq!(
        ::std::mem::size_of::<rtls_tdx_evidence>(),
        0usize,
        concat!("Size of: ", stringify!(rtls_tdx_evidence))
    );
    assert_eq!(
        ::std::mem::align_of::<rtls_tdx_evidence>(),
        1usize,
        concat!("Alignment of ", stringify!(rtls_tdx_evidence))
    );
}
pub type rtls_tdx_evidence_t = rtls_tdx_evidence;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ehd {
    pub public_key: *mut ::std::os::raw::c_void,
    pub user_data_size: ::std::os::raw::c_int,
    pub user_data: *mut ::std::os::raw::c_char,
    pub unhashed_size: ::std::os::raw::c_int,
    pub unhashed: *mut ::std::os::raw::c_char,
}
#[test]
fn bindgen_test_layout_ehd() {
    assert_eq!(
        ::std::mem::size_of::<ehd>(),
        40usize,
        concat!("Size of: ", stringify!(ehd))
    );
    assert_eq!(
        ::std::mem::align_of::<ehd>(),
        8usize,
        concat!("Alignment of ", stringify!(ehd))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ehd>())).public_key as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(ehd),
            "::",
            stringify!(public_key)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ehd>())).user_data_size as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(ehd),
            "::",
            stringify!(user_data_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ehd>())).user_data as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(ehd),
            "::",
            stringify!(user_data)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ehd>())).unhashed_size as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(ehd),
            "::",
            stringify!(unhashed_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ehd>())).unhashed as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(ehd),
            "::",
            stringify!(unhashed)
        )
    );
}
pub type ehd_t = ehd;
pub const enclave_evidence_type_t_SGX_ECDSA: enclave_evidence_type_t = 1;
pub const enclave_evidence_type_t_TDX: enclave_evidence_type_t = 2;
pub type enclave_evidence_type_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct rtls_evidence {
    pub type_: enclave_evidence_type_t,
    pub ehd: ehd_t,
    pub quote_size: ::std::os::raw::c_int,
    pub quote: *mut ::std::os::raw::c_char,
    pub __bindgen_anon_1: rtls_evidence__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union rtls_evidence__bindgen_ty_1 {
    pub sgx: rtls_sgx_evidence_t,
    pub tdx: rtls_tdx_evidence_t,
}
#[test]
fn bindgen_test_layout_rtls_evidence__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<rtls_evidence__bindgen_ty_1>(),
        48usize,
        concat!("Size of: ", stringify!(rtls_evidence__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<rtls_evidence__bindgen_ty_1>(),
        8usize,
        concat!("Alignment of ", stringify!(rtls_evidence__bindgen_ty_1))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence__bindgen_ty_1>())).sgx as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence__bindgen_ty_1),
            "::",
            stringify!(sgx)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence__bindgen_ty_1>())).tdx as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence__bindgen_ty_1),
            "::",
            stringify!(tdx)
        )
    );
}
#[test]
fn bindgen_test_layout_rtls_evidence() {
    assert_eq!(
        ::std::mem::size_of::<rtls_evidence>(),
        112usize,
        concat!("Size of: ", stringify!(rtls_evidence))
    );
    assert_eq!(
        ::std::mem::align_of::<rtls_evidence>(),
        8usize,
        concat!("Alignment of ", stringify!(rtls_evidence))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence>())).ehd as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence),
            "::",
            stringify!(ehd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence>())).quote_size as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence),
            "::",
            stringify!(quote_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<rtls_evidence>())).quote as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(rtls_evidence),
            "::",
            stringify!(quote)
        )
    );
}

pub type rtls_evidence_t = rtls_evidence;
pub type rats_tls_callback_t = ::std::option::Option<
    unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void) -> ::std::os::raw::c_int,
>;

extern "C" {
    pub fn rats_tls_init(
        conf: *const rats_tls_conf_t,
        handle: *mut *mut rats_tls_handle,
    ) -> rats_tls_err_t;

    pub fn rats_tls_set_verification_callback(
        handle: *mut *mut rats_tls_handle,
        user_callback: rats_tls_callback_t,
    ) -> rats_tls_err_t;

    pub fn rats_tls_negotiate(
        handle: *const rats_tls_handle,
        fd: ::std::os::raw::c_int,
    ) -> rats_tls_err_t;

    pub fn rats_tls_receive(
        handle: *const rats_tls_handle,
        buf: *mut ::std::os::raw::c_void,
        buf_size: *mut size_t,
    ) -> rats_tls_err_t;

    pub fn rats_tls_transmit(
        handle: *const rats_tls_handle,
        buf: *const ::std::os::raw::c_void,
        buf_size: *mut size_t,
    ) -> rats_tls_err_t;

    pub fn rats_tls_cleanup(
        handle: *mut rats_tls_handle
    ) -> rats_tls_err_t;
}
