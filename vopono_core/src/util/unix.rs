use anyhow::{Context, Result, anyhow};
use libc::{self, CLONE_NEWNS, execvp, pid_t};
use std::ffi::CString;
use std::fs::File;
use std::io::Error as IoError;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;

pub fn run_program_in_netns_with_path_redirect(
    program: &str,
    args: &[&str],
    netns_name: &str,
    original_path: &str,
    new_path: &str,
) -> Result<u32> {
    // TODO: We could receive netns file descriptor from the caller
    // Validate that network namespace exists
    let netns_path = format!("/var/run/netns/{netns_name}");
    if !Path::new(&netns_path).exists() {
        return Err(anyhow!("Network namespace '{netns_name}' does not exist"));
    }

    // Open the network namespace file descriptor
    let netns_fd = File::open(&netns_path)
        .with_context(|| format!("Failed to open network namespace file: {netns_path}"))?;

    // Fork a new process
    let pid: pid_t = unsafe { libc::fork() };

    match pid.cmp(&0) {
        std::cmp::Ordering::Less => {
            // Fork failed
            Err(anyhow!("Fork failed: {}", IoError::last_os_error()))
        }
        std::cmp::Ordering::Equal => {
            // Child process

            // Set network namespace
            let result = unsafe { libc::setns(netns_fd.as_raw_fd(), libc::CLONE_NEWNET) };
            if result == -1 {
                eprintln!(
                    "Failed to set network namespace: {}",
                    IoError::last_os_error()
                );
                unsafe { libc::_exit(1) };
            }

            // Create new mount namespace
            let res = unsafe { libc::unshare(CLONE_NEWNS) };
            if res == -1 {
                eprintln!("Unshare failed: {}", IoError::last_os_error());
                unsafe { libc::_exit(1) };
            }

            // Make root private
            let root = CString::new("/")?;
            let result = unsafe {
                libc::mount(
                    ptr::null(),
                    root.as_ptr(),
                    ptr::null(),
                    libc::MS_PRIVATE | libc::MS_REC,
                    ptr::null(),
                )
            };
            if result == -1 {
                eprintln!("Making root private failed: {}", IoError::last_os_error());
                unsafe { libc::_exit(1) };
            }

            // Create mount binding for path redirection
            let source = CString::new(new_path)?;
            let target = CString::new(original_path)?;
            let result = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND,
                    ptr::null(),
                )
            };
            if result == -1 {
                eprintln!("Bind mount failed: {}", IoError::last_os_error());
                unsafe { libc::_exit(1) };
            }

            // Replace current process with target program using execvp
            let program_cstr = CString::new(program)?;

            // Convert args to C strings
            let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
            c_args.push(program_cstr.clone()); // First arg is program name

            for arg in args {
                c_args.push(CString::new(*arg)?);
            }

            // Convert to C-style array of pointers
            let mut arg_ptrs: Vec<*const c_char> = c_args.iter().map(|arg| arg.as_ptr()).collect();
            arg_ptrs.push(std::ptr::null());

            unsafe {
                execvp(program_cstr.as_ptr(), arg_ptrs.as_ptr());
                // If we get here, execvp failed
                eprintln!("execvp failed: {}", IoError::last_os_error());
                libc::_exit(1);
            }
        }
        std::cmp::Ordering::Greater => {
    // Parent process - return the child PID without blocking
            Ok(pid as u32)
        }
    }

}
