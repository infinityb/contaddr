use std::io::{self, Read, Write, Seek, SeekFrom};
use std::os::unix::io::{RawFd, AsRawFd, FromRawFd};
use std::fs::{File, Metadata};
use std::path::Path;

const AT_FDCWD: libc::c_int =  -100;
const AT_SYMLINK_FOLLOW: libc::c_int = 0o2000;

const O_PATH: libc::c_int = 0o10000000;
const O_TMPFILE: libc::c_int = 0o20200000;
const O_CLOEXEC: libc::c_int =  0o2000000;
const O_DIRECTORY: libc::c_int =   0o200000;

use ::libc::{self, c_int, O_RDWR};
use ::openssl::crypto::hash::{Hasher, Type};
use ::rustc_serialize::hex::ToHex;

#[derive(Debug)]
struct Directory(RawFd);

impl Drop for Directory {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl Directory {
    fn open<P: AsRef<Path>>(dir: P) -> io::Result<Directory> {
        ::ffi::open(dir, O_CLOEXEC | O_DIRECTORY, 0).map(Directory)
    }
}

fn create_linkable_at(dir: &Directory) -> io::Result<File> {
    ::ffi::openat(dir.0, ".", O_CLOEXEC | O_TMPFILE | O_RDWR, 0)
        .map(|fd| unsafe { FromRawFd::from_raw_fd(fd) })
}

#[derive(Debug)]
pub struct Address(String);

pub struct ContAddr {
    dir: Directory,
    digest: Type,
}

impl ContAddr {
    pub fn open<P: AsRef<Path>>(dir: P, digest: Type) -> io::Result<ContAddr> {
        let contaddr = Directory::open(dir).map(|d| ContAddr { dir: d, digest: digest });
        if let Ok(ref contaddr) = contaddr {
            let mut buffer: [u8; 2] = [0; 2];
            for i in 0..256 {
                write!(&mut io::Cursor::new(&mut buffer[..]), "{:02x}", i);
                let filename = ::std::str::from_utf8(&buffer).unwrap();
                contaddr.mkdir(filename).unwrap();
            }
        }
        contaddr
    }

    pub fn create(&self) -> io::Result<TempFile> {
        create_linkable_at(&self.dir).map(TempFile)
    }

    fn mkdir(&self, address: &str) -> io::Result<()> {
        if address.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "address must be at least two characters"))
        }

        let Directory(dir_fd) = self.dir;

        let mut buffer: [u8; 4] = [0; 4];
        write!(
            &mut io::Cursor::new(&mut buffer[..]),
            "./{}", &address[0..2]);
        let directory_name = ::std::str::from_utf8(&buffer).unwrap();

        match ::ffi::mkdirat(dir_fd, directory_name, 0o700) {
            Ok(()) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn commit(&self, mut target: TempFile) -> io::Result<Address> {
        try!(target.seek(SeekFrom::Start(0)));
        let address = {
            let mut h = Hasher::new(self.digest);
            try!(io::copy(&mut target, &mut h));
            h.finish().to_hex()
        };

        let Directory(dir_fd) = self.dir;
        let proc_filename = format!("/proc/self/fd/{}", target.0.as_raw_fd());
        let target_filename = format!("./{}/{}", &address[0..2], address);
        try!(::ffi::fchmod(target.0.as_raw_fd(), 0o644));
        let linkat_rv = ::ffi::linkat(
            AT_FDCWD, &proc_filename,
            dir_fd, &target_filename,
            AT_SYMLINK_FOLLOW);
        
        linkat_rv
            .map(|()| Address(address))
            .map_err(|e| if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(io::ErrorKind::AlreadyExists, target_filename)
            } else {
                e
            })
    }
}

#[derive(Debug)]
pub struct TempFile(File);

impl TempFile {
    /// Number of bytes in the file.
    #[inline]
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.0.metadata()
    }

    /// Truncates or extends the underlying file, updating the size of this
    /// file to become `size`.
    #[inline(always)]
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }
}

impl Read for TempFile {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TempFile {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Seek for TempFile {
    #[inline(always)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use rand::{self, Rng, XorShiftRng};
    use super::ContAddr;

    fn random_buffer(testsize: usize) -> Vec<u8> {
        let mut fast_rng: XorShiftRng = rand::thread_rng().gen();

        let mut buf = vec![0; testsize];
        fast_rng.fill_bytes(&mut buf[..]);
        buf
    }

    #[test]
    fn random_test() {
        // This fails in a test for some reason. It works outside. ???
        
        let buf = random_buffer(100 * 1024);

        let contaddr = ContAddr::open("/tmp/x").unwrap();

        let mut wri = contaddr.create().unwrap();
        io::copy(&mut io::Cursor::new(&buf[..]), &mut wri).unwrap();
        contaddr.commit(wri).unwrap();
    }
}

