#![feature(convert)]

extern crate libc;
extern crate openssl;
extern crate rustc_serialize;
extern crate rand;
extern crate time;

mod contaddr;
mod ffi;

pub use contaddr::{ContAddr, TempFile, Staged, Address};
pub use ::openssl::crypto::hash::Type as HashType;
