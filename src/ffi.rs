// Copyright (c) 2021 Open Information Security Foundation
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

/// Helper module for this plugin to provide better interfaces to the C API.
/// This will become part of the Suricata dependency crate at some point.
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::str::Utf8Error;

// Rust representation of a C plugin.
#[repr(C)]
pub struct SCPlugin {
    name: *const c_char,
    license: *const c_char,
    author: *const c_char,
    init: unsafe extern "C" fn(),
}

impl SCPlugin {
    pub fn new(
        name: &str,
        license: &str,
        author: &str,
        init_fn: unsafe extern "C" fn(),
    ) -> *const Self {
        let name = CString::new(name).unwrap();
        let license = CString::new(license).unwrap();
        let author = CString::new(author).unwrap();
        let plugin = SCPlugin {
            name: name.into_raw(),
            license: license.into_raw(),
            author: author.into_raw(),
            init: init_fn,
        };
        Box::into_raw(Box::new(plugin))
    }
}

pub type OpenFn = unsafe extern "C" fn(conf: *const c_void, init_data: *mut *mut c_void) -> c_int;
pub type CloseFn = unsafe extern "C" fn(init_data: *const c_void);
pub type WriteFn = unsafe extern "C" fn(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
) -> c_int;

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCPluginFileType {
    pub name: *const c_char,
    pub open: OpenFn,
    pub write: WriteFn,
    pub close: CloseFn,

    // Pad for the TAILQ datastructure. This will not be required in 7.0.
    pad0: usize,
    pad1: usize,
}

impl SCPluginFileType {
    pub fn new(name: &str, open: OpenFn, close: CloseFn, write: WriteFn) -> *const Self {
        // Convert the name to C and forget.
        let name = CString::new(name).unwrap().into_raw();
        let file_type = SCPluginFileType {
            name,
            open,
            close,
            write,
            pad0: 0,
            pad1: 0,
        };
        Box::into_raw(Box::new(file_type))
    }
}

extern "C" {
    pub fn SCPluginRegisterFileType(filetype: *const SCPluginFileType) -> bool;
}

// Convert a C string with a provided length to a Rust &str.
//
// This is an alternative to CStr::from_ptr when the length is already known to avoid the
// scan of the string to find the length (strlen).
pub fn str_from_c_parts<'a>(
    buffer: *const c_char,
    buffer_len: c_int,
) -> Result<&'a str, Utf8Error> {
    unsafe {
        CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
            buffer as *const u8,
            buffer_len as usize + 1,
        ))
        .to_str()
    }
}
