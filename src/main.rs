mod handlers;
mod syscalls;

use clap::{app_from_crate, arg, App, AppSettings};
use ctrlc;
use nix::{
    self,
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{self, ForkResult},
};
use std::os::unix::fs::FileTypeExt;
use std::{env, error::Error, ffi::CString};

use syscalls::Syscall;

/// The result returned by a call to `wait_for_syscall`.
pub enum SyscallWaitResult {
    // Indicates that a syscall was made
    Syscall(i64),

    // Indicates that the process was terminated
    Terminated,
}

/// Wait for the attached process to perform a syscall.
pub fn wait_for_syscall(pid: unistd::Pid) -> nix::Result<SyscallWaitResult> {
    loop {
        ptrace::syscall(pid, None)?;
        match waitpid(pid, None)? {
            WaitStatus::PtraceSyscall(..) => {
                // Extract the syscall number from the
                // RAX register
                let regs = ptrace::getregs(pid)?;
                return Ok(SyscallWaitResult::Syscall(regs.orig_rax as i64));
            }
            WaitStatus::Exited(..) => return Ok(SyscallWaitResult::Terminated),

            // The process state changed for some other reason
            _ => continue,
        }
    }
}

/// Run a command in a new child process and attach norand
/// to it.
fn launch(prog: &str, args: Vec<&str>, source: &str) -> Result<(), Box<dyn Error>> {
    match unsafe { unistd::fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            // Wait until the child process has set itself as traceable
            let _ = waitpid(child, None)?;
            monitor_process(child, source)
        }
        Ok(ForkResult::Child) => {
            // Set the process as traceable
            ptrace::traceme()?;

            let pathname = CString::new(prog).unwrap();
            let argv: Vec<CString> = vec![&prog]
                .into_iter()
                .chain(args.iter())
                .map(|x| CString::new(*x).unwrap())
                .collect();

            let envp: Vec<CString> = env::vars()
                .map(|(k, v)| format!("{:?}={:?}", k, v))
                .map(|v| CString::new(v).unwrap())
                .collect();

            let _ = unistd::execvpe(&pathname, &argv, &envp);

            Ok(())
        }
        Err(e) => Err(Box::new(e)),
    }
}

/// Attach to an existing PID
fn attach(pid: unistd::Pid, source: &str) -> Result<(), Box<dyn Error>> {
    // Attach to another process using PTRACE_ATTACH, and then
    // start monitoring it.
    println!("Attaching to {:?}", pid);
    ptrace::attach(pid)?;

    // We register a new signal handler that detaches the program
    // from the process it's operating on when we exit
    ctrlc::set_handler(move || {
        println!("Detaching from process...");
        match ptrace::detach(pid, None) {
            Err(e) => {
                eprintln!("Error detaching from {:?}: {:?}", pid, e);
                std::process::exit(1);
            }
            Ok(_) => {
                std::process::exit(0);
            }
        };
    })
    .expect("Error registering signal handler");

    // Start monitoring the attached process
    monitor_process(pid, source)?;

    Ok(())
}

/// Monitor ptrace events on a target process
fn monitor_process(pid: unistd::Pid, source: &str) -> Result<(), Box<dyn Error>> {
    // We set the PTRACE_O_TRACESYSGOOD option to make it easy to distinguish
    // between syscall traps and regular traps (see ptrace(2))
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

    loop {
        match wait_for_syscall(pid)? {
            SyscallWaitResult::Syscall(num) => {
                // Use a different handler based on which syscall
                // we received
                match Syscall::try_from(num) {
                    Ok(sc) => handlers::handle_syscall(sc, pid, source)?,
                    Err(_) => println!("Received invalid syscall ID: {:?}", num),
                }
            }
            SyscallWaitResult::Terminated => {
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = app_from_crate!()
        .about("Replace the OS random streams for a process")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(
            arg!(-s --source [PIPE] "Source of randomness that should be used")
                .required(false)
                .default_value("/dev/zero"),
        )
        .subcommand(
            App::new("run")
                .setting(AppSettings::TrailingVarArg)
                .setting(AppSettings::AllowHyphenValues)
                .about("Start a new process")
                .arg(arg!([PROGRAM]).required(true))
                .arg(
                    arg!([ARGS])
                        .required(false)
                        .takes_value(true)
                        .multiple_values(true),
                ),
        )
        .subcommand(
            App::new("attach")
                .about("Attaching to an existing process")
                .arg(arg!([PID]).required(true)),
        );

    let matches = app.get_matches();
    let source = matches.value_of("source").unwrap();
    let ft = std::fs::metadata(source)?.file_type();

    if !ft.is_char_device() && !ft.is_fifo() {
        eprintln!("The input --source must be a character device or FIFO pipe");
        std::process::exit(1);
    }

    if let Some(m) = matches.subcommand_matches("run") {
        let prog = m.value_of("PROGRAM").unwrap();
        let args: Vec<&str> = match m.values_of("ARGS") {
            Some(args) => args.collect(),
            None => vec![],
        };

        launch(prog, args, source)?;
    } else if let Some(m) = matches.subcommand_matches("attach") {
        let pid_str = m.value_of("PID").unwrap();
        match pid_str.parse::<i32>() {
            Ok(pid) => {
                attach(unistd::Pid::from_raw(pid), source)?;
            }
            Err(_) => {
                eprintln!("{:?} is not a valid PID", pid_str);
            }
        }
    }

    Ok(())
}
