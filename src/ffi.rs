use std::io;
use std::ffi::CString;
use std::path::Path;
use std::os::unix::io::RawFd;
use libc::{self, mode_t, c_int};


mod internal {
    use libc::{mode_t, c_char, c_int};

    #[link(name = "c")]
    extern {
        pub fn linkat(
            olddirfd: c_int,
            oldpath: *const c_char,
            newdirfd: c_int,
            newpath: *const c_char,
            flags: c_int) -> c_int;

        pub fn mkdirat(
            dirfd: c_int,
            pathname: *const c_char,
            mode: mode_t) -> c_int;

        pub fn openat(
            dirfd: c_int,
            pathname: *const c_char,
            flags: c_int,
            mode: mode_t) -> c_int;

        pub fn unlinkat(
            dirfd: c_int,
            pathname: *const c_char,
            flags: c_int) -> c_int;

        pub fn fchmod(
            fd: c_int,
            mode: mode_t) -> c_int;
    }
}

// Stolen from stdlib
fn cstr(path: &Path) -> io::Result<CString> {
    path.as_os_str().to_cstring().ok_or(
        io::Error::new(io::ErrorKind::InvalidInput, "path contained a null"))
}

fn last_error_wpath(target: &Path) -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(2) => io::Error::new(io::ErrorKind::NotFound, format!("{:?}", target)),
        Some(17) => io::Error::new(io::ErrorKind::AlreadyExists, format!("{:?}", target)),
        _ => err
    }
}

fn last_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(2) => io::Error::new(io::ErrorKind::NotFound, "File not found"),
        Some(17) => io::Error::new(io::ErrorKind::AlreadyExists, "File already exists"),
        _ => err
    }
}

pub fn linkat<P1: AsRef<Path>, P2: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P1,
    newdirfd: RawFd,
    newpath: P2,
    flags: c_int
) -> io::Result<()> {
    let oldpath = try!(cstr(oldpath.as_ref()));
    let newpath = try!(cstr(newpath.as_ref()));
    let rv = unsafe { internal::linkat(
        olddirfd, oldpath.as_ptr(), newdirfd, newpath.as_ptr(), flags) };
    match rv {
        -1 => Err(last_error()),
        _ => Ok(()),
    }
}

pub fn mkdirat<P: AsRef<Path>>(
    dirfd: RawFd,
    pathname: P,
    mode: mode_t
) -> io::Result<()> {
    let cpathname = try!(cstr(pathname.as_ref()));
    match unsafe { internal::mkdirat(dirfd, cpathname.as_ptr(), mode) } {
        -1 => Err(last_error_wpath(pathname.as_ref())),
        0 => Ok(()),
        _ => unreachable!(),
    }
}

pub fn openat<P: AsRef<Path>>(
    dirfd: RawFd,
    pathname: P,
    flags: c_int,
    mode: mode_t
) -> io::Result<RawFd> {
    let cpathname = try!(cstr(pathname.as_ref()));
    let rv = unsafe { internal::openat(dirfd, cpathname.as_ptr(), flags, mode) };
    match rv {
        -1 => Err(last_error_wpath(pathname.as_ref())),
        fd => Ok(fd),
    }
}

pub fn unlinkat<P: AsRef<Path>>(
    dirfd: RawFd,
    pathname: P,
    flags: c_int,
) -> io::Result<()> {
    let cpathname = try!(cstr(pathname.as_ref()));
    let rv = unsafe { internal::unlinkat(dirfd, cpathname.as_ptr(), flags) };
    match rv {
        -1 => Err(last_error_wpath(pathname.as_ref())),
        0 => Ok(()),
        _ => unreachable!(),
    }
}
pub fn fchmod(dirfd: RawFd, mode: mode_t) -> io::Result<()> {
    let rv = unsafe { internal::fchmod(dirfd, mode) };
    match rv {
        -1 => Err(last_error()),
        0 => Ok(()),
        _ => unreachable!(),
    }
}

pub fn open<P: AsRef<Path>>(
    dir: P,
    flags: c_int,
    mode: mode_t
) -> io::Result<RawFd> {
    let dir_cstr = try!(cstr(dir.as_ref()));
    match unsafe { libc::open(dir_cstr.as_ptr(), flags, mode) } {
        -1 => Err(last_error_wpath(dir.as_ref())),
        fd => Ok(fd)
    }
}
