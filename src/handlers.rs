//! Definitions of handlers for various syscalls, and
//! related utilities.

use crate::syscalls::Syscall;
use core::ffi::c_void;
use nix::{
    sys::{ptrace, wait::waitpid},
    unistd,
};
use std::{error::Error, fs::File, io::Read, mem};

/// Representation of a word from process memory.
#[repr(C)]
union Word {
    v: i64,
    buf: [u8; 8],
}

type HandlerResult<T> = Result<T, Box<dyn Error>>;

/// Dispatcher for syscall handlers
pub fn handle_syscall(sc: Syscall, pid: unistd::Pid, source: &str) -> HandlerResult<()> {
    match sc {
        Syscall::open => sc_handler_open(pid, source),
        Syscall::openat => sc_handler_openat(pid, source),
        Syscall::getrandom => sc_handler_getrandom(pid, source),

        // Syscalls not covered by the other branches don't have a
        // handler
        _ => Ok(()),
    }
}

/// Copy a string from the attached process's memory
fn ptrace_copy_str(pid: unistd::Pid, mut addr: ptrace::AddressType) -> nix::Result<String> {
    // Create a buffer to hold the string
    let mut buf = vec![];

    loop {
        let val = ptrace::read(pid, addr)?;
        let word = Word { v: val };

        // Append bytes from the word buffer to the string
        let mut word_buf: Vec<u8> = unsafe { word.buf }
            .iter()
            .take_while(|&c| *c != 0)
            .map(|c| *c)
            .collect();

        let bytes_read = word_buf.len();
        buf.append(&mut word_buf);

        if bytes_read != mem::size_of::<Word>() {
            break;
        }

        unsafe {
            addr = addr.offset(word.buf.len().try_into().unwrap());
        }
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// Write a buffer into the attached process's memory at a given address.
fn ptrace_write_buf(
    pid: unistd::Pid,
    mut addr: ptrace::AddressType,
    buf: &[u8],
) -> nix::Result<()> {
    for chunk in buf.chunks(mem::size_of::<Word>()) {
        // Pad chunk if needed to meet the word size
        let mut word = Word { buf: [0; 8] };

        unsafe {
            word.buf[..chunk.len()].copy_from_slice(chunk);
            ptrace::write(pid, addr, word.v as *mut c_void)?;
            addr = addr.offset(mem::size_of::<Word>().try_into().unwrap());
        }
    }

    Ok(())
}

/// Handler for the `open` syscall.
fn sc_handler_open(pid: unistd::Pid, source: &str) -> HandlerResult<()> {
    // Read the address for where the path is stored
    // from RDI
    let mut regs = ptrace::getregs(pid)?;
    let addr: *mut c_void = regs.rdi as *mut c_void;
    let path = ptrace_copy_str(pid, addr)?;

    // If the path matches /dev/random or /dev/urandom,
    // we redirect it to our random source
    if path == "/dev/random" || path == "/dev/urandom" {
        // Put a string with the path to our source on the stack
        let mut new_path = source.as_bytes().to_vec();
        new_path.push(0u8);

        let stack_addr: *mut c_void = regs.rsp as *mut c_void;
        let path_len: isize = new_path.len().try_into()?;
        let new_path_addr = unsafe { stack_addr.offset(-path_len) };

        ptrace_write_buf(pid, new_path_addr, &new_path)?;

        // Point RSI towards the new string
        regs.rdi = new_path_addr as u64;
        ptrace::setregs(pid, regs)?;
    }

    Ok(())
}

/// Handler for the `openat` syscall.
fn sc_handler_openat(pid: unistd::Pid, source: &str) -> HandlerResult<()> {
    // Read the address for where the path is stored
    // from RSI
    let mut regs = ptrace::getregs(pid)?;
    let addr: *mut c_void = regs.rsi as *mut c_void;
    let path = ptrace_copy_str(pid, addr)?;

    // If the path matches /dev/random or /dev/urandom,
    // we redirect it to our random source
    if path == "/dev/random" || path == "/dev/urandom" {
        // Put a string with the path to our source on the stack
        let mut new_path = source.as_bytes().to_vec();
        new_path.push(0u8);

        let stack_addr: *mut c_void = regs.rsp as *mut c_void;
        let path_len: isize = new_path.len().try_into()?;
        let new_path_addr = unsafe { stack_addr.offset(-path_len) };

        ptrace_write_buf(pid, new_path_addr, &new_path)?;

        // Point RSI towards the new string
        regs.rsi = new_path_addr as u64;
        ptrace::setregs(pid, regs)?;
    }

    Ok(())
}

/// Handler for the `getrandom` syscall.
fn sc_handler_getrandom(pid: unistd::Pid, source: &str) -> HandlerResult<()> {
    // Read the address of the destination buffer from RDI
    let regs = ptrace::getregs(pid)?;
    let buf_addr: *mut c_void = regs.rdi as *mut c_void;

    // Step the attached process forward one instruction so that
    // the syscall executes
    ptrace::step(pid, None)?;
    waitpid(pid, None)?;

    // Copy data from our random source into the destination buffer
    let nbytes: usize = ptrace::getregs(pid)?.rax.try_into()?;
    let mut buf = vec![0u8; nbytes];
    let mut f = File::open(source)?;
    f.read(&mut buf)?;

    ptrace_write_buf(pid, buf_addr, buf.as_slice())?;

    Ok(())
}
