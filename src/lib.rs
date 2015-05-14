#![feature(convert)]

extern crate libc;
extern crate openssl;
extern crate rustc_serialize;
extern crate rand;

mod contaddr;
mod ffi;

pub use contaddr::{ContAddr, TempFile};
pub use ::openssl::crypto::hash::Type;
