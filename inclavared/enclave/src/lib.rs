/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#![crate_name = "inclavaredenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    let rust_raw_string = "This is a in-Enclave ";
    let word:[u8;4] = [82, 117, 115, 116];
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    let mut hello_string = String::from(rust_raw_string);

    for c in word.iter() {
        hello_string.push(*c as char);
    }

    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}
