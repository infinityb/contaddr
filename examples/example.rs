extern crate contaddr;
extern crate rand;

use std::io::{self, Read, Write};
use std::thread::sleep_ms;
use rand::{Rng, XorShiftRng};
use contaddr::ContAddr;

fn random_buffer(testsize: usize) -> Vec<u8> {
    let mut fast_rng: XorShiftRng = rand::thread_rng().gen();

    let mut buf = vec![0; testsize];
    fast_rng.fill_bytes(&mut buf[..]);
    buf
}

fn main() {
    let contaddr = ContAddr::open("/home/sell/contaddr", contaddr::Type::SHA256).unwrap();

    for _ in 0..5000 {
        let buf = random_buffer(40 * 1024);
        let mut wri = contaddr.create().unwrap();
        io::copy(&mut io::Cursor::new(&buf[..]), &mut wri).unwrap();
        contaddr.commit(wri).unwrap();
    }

}