use windows_drives::drive::{PhysicalDrive, DiskGeometry};
use windows_drives::win32;
use windows_drives::win32::last_error;
use windows::{
    core::PCWSTR,
    Win32::Storage::FileSystem::{WriteFile, ReadFile, CreateFileW, SetFilePointerEx, FILE_BEGIN, FILE_ACCESS_FLAGS, FILE_SHARE_MODE, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES},
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle},
};
use sysinfo::{SystemExt};
use powershell_script;
use clap::Arg;
use std::time::{Instant};
use std::{
    ptr::{null_mut, null},
    process::exit
};
use winapi::{
    shared::minwindef::{DWORD, LPVOID},
    um::{
        fileapi::{OPEN_EXISTING},
        winbase::{FILE_FLAG_NO_BUFFERING},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        memoryapi::VirtualAlloc
    },
};
use std::thread;
use std::string::String;
use std::sync::mpsc::{channel, Sender, Receiver};

// TODO: Add params for chunk size, refactoring to combine thread read and write

const MEGABYTE: u64 = 1048576;

fn main() {
    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    let args = clap::App::new("Physical Disk IO")
        .version("v1.1.0")
        .author("Arjun Srivastava, Microsoft CHIE - ASE")
        .about("CLI to conduct multithreaded read/write IO operations on single-partition physical disks")
        .arg(Arg::new("write")
            .short('w')
            .long("write")
            .takes_value(true)
            .help("Specify physical disk ID to write to"))
        .arg(Arg::new("threads")
            .short('t')
            .long("threads")
            .takes_value(true)
            .help("Number of threads to use"))
        .arg(Arg::new("read")
            .short('r')
            .long("read")
            .takes_value(true)
            .help("Specify physical disk ID to read from"))
        .get_matches();

    let partitions: u8;
    let disk_number: u8;
    let mut threads: u64 = 1;
    let io_type: char;
    if args.is_present("threads") {
        threads = args.value_of("threads").unwrap().parse().expect("Number of threads must be a valid integer");
    }
    if args.is_present("read") {
        disk_number = args.value_of("read").unwrap().parse().expect("Disk number must be a valid integer!");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            println!("Cannot conduct read IO operations on disk with multiple partitions, exiting...");
            exit(1);
        }
        io_type = 'r';
    } else if args.is_present("write") {
        disk_number = args.value_of("write").unwrap().parse().expect("Disk number must be a valid integer!");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            println!("Cannot conduct write IO operations on disk with multiple partitions, exiting...");
            exit(1);
        }
        io_type = 'w';
    } else {
        println!("Please specify an IO operation (see --help for more information)");
        exit(0);
    }
    let num_threads = threads;
    let (sender, receiver): (Sender<String>, Receiver<String>) = channel();
    let (size, io_size, sector_size) = calculate_disk_info(disk_number);
    println!("Disk {} size: {} bytes", disk_number, size);
    while threads != 0 {
        let sen_clone = sender.clone();
        if io_type == 'r' {
            thread::spawn(move || thread_read(sen_clone, disk_number, num_threads, threads.clone(), size, io_size, sector_size));
        } else if io_type == 'w' {
            thread::spawn(move || thread_write(sen_clone, disk_number, num_threads, threads.clone(), size, io_size, sector_size));
        }
        threads -= 1;
    }
    // Use sender/receiver model to track thread progress
    let receiver_thread = thread::spawn(move|| {
        let mut threads_clone = threads.clone();
        for i in receiver {
            let isplit = i.split("|");
            if isplit.clone().next().unwrap()=="finished" {
                println!("[Thread {}]: Status: {}", isplit.clone().last().unwrap(), isplit.clone().next().unwrap());
                threads_clone -= 1;
                if threads_clone == 0 {
                    println!("{}", "Task is finished!");
                    break;
                }
            }
        }
    });
    receiver_thread.join().unwrap();

    // let output = powershell_script::run(r#"
    //         Get-PhysicalDisk | Sort-Object -Property { [int]$_.DeviceId } | Select-Object DeviceId
    //         "#).unwrap();
    // let output_string = output.stdout().unwrap();

}

// Use powershell script to get number partitions for a given physical disk
fn get_partitions(disk_number: u8) -> u8 {
    let ps_script = format!("[array]$Partitions = Get-Partition {}
                            Write-Output ($Partitions.count)", disk_number);
    let output = powershell_script::run(&ps_script).unwrap();
    let mut output_string: String = output.stdout().unwrap();
    output_string = (*output_string.trim()).to_string();
    let partition_number: u8 = output_string.parse().unwrap();
    return partition_number;
}

// Leverage Win32 to open a physical drive handle for writing
fn open_handle(path: &str, handle_type: char) -> Result<HANDLE, String> {
    let path = win32::win32_string(&path);
    let handle_template = HANDLE(0);    // Generic hTemplate needed for CreateFileW
    let path_ptr: PCWSTR = PCWSTR(path.as_ptr() as *const u16);
    let handle: HANDLE;
    if handle_type == 'w' {
        handle = unsafe {
            CreateFileW(
                path_ptr,
                FILE_ACCESS_FLAGS(GENERIC_WRITE | GENERIC_READ),
                FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
                null(),     // Security attributes not needed
                FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_NO_BUFFERING),
                handle_template,
            ).unwrap()
        };
    } else {
        handle = unsafe {
            CreateFileW(
                path_ptr,
                FILE_ACCESS_FLAGS(GENERIC_READ),
                FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
                null(),     // Security attributes not needed
                FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_NO_BUFFERING),
                handle_template,
            ).unwrap()
        }
    }
    if handle == INVALID_HANDLE_VALUE {
        let err = win32::last_error();
        Err(match err {
            2 => "could not open handle because the device was not found".to_string(),
            5 => "could not open handle because access was denied - do you have administrator privileges?".to_string(),
            _ => format!("got invalid handle: error code {:#08x}", err)
        })
    } else {
        Ok(handle)
    }
}


// Format drive number for Win32 API
fn format_drive_num(drive_num: u8) -> String {
    return format!("\\\\.\\PhysicalDrive{}", drive_num);
}


// Conduct multithreaded write operation
fn thread_write(senderr: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, size: u64, writesize: u64, sector_size: u64) {
    println!("Starting thread {}", id);    // For debugging purposes
    let full_write_size = size / num_threads;
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'w').unwrap();

    // Set up FilePointer to start write at offset based on thread number
    let mut offset = (id - 1) * full_write_size;
    
    // Reset offset if not an even multiple of sector size
    offset = calculate_io_size(sector_size, offset);

    let _pointer = unsafe {
        SetFilePointerEx(
            handle,
            (MEGABYTE + offset) as i64,     // Increase offset by 1 MB to avoid overwriting index table and other initialization data
            null_mut(),
            FILE_BEGIN
        )
    };

    // Allocate sector-aligned buffer with Win32 VirtualAlloc
    let buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            writesize as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    let mut bytes_written: u32 = 0;      // Start at 1 MB offset
    let bytes_written_ptr: *mut u32 = &mut bytes_written;
    let mut pos: u64 = offset;
    // println!("Thread {} First position: {}", id, offset);
    let last_pos = full_write_size * id - writesize;
    // println!("Thread {} Last position: {}", id, last_pos);

    let now = Instant::now();
    while pos <= last_pos {
        let write = unsafe {
            WriteFile(
                handle,
                buffer,
                writesize as DWORD,
                bytes_written_ptr,
                null_mut()
            )
        };
        pos += bytes_written as u64;
        // pos += writesize;
        if write == false && last_error() != 997 {      // Error code 997 (ERROR_IO_PENDING) is non fatal
            println!("Thread {} encountered Error Code {}", id, last_error());
            break;
        }
    }
    let elapsed_time = now.elapsed();
    println!("Thread {} took {} seconds to finish", id, elapsed_time.as_secs());
    unsafe {
        CloseHandle(handle);
    }
    senderr.send(format!("finished|{}", id)).unwrap();
}


// Conduct multithreaded read operation
fn thread_read(senderr: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, size: u64, readsize: u64, sector_size: u64) {
    println!("Starting thread {}", id);    // For debugging purposes
    let full_read_size = size / num_threads;
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'r').unwrap();

    // Set up FilePointer to start read at offset based on thread number
    let mut offset = (id - 1) * full_read_size;

    // Reset offset if not an even multiple of sector size
    offset = calculate_io_size(sector_size, offset);

    let _pointer = unsafe {
        SetFilePointerEx(
            handle,
            offset as i64,
            null_mut(),
            FILE_BEGIN
        )
    };

    let buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            readsize as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    let mut bytes_read: u32 = 0;
    let bytes_read_ptr: *mut u32 = &mut bytes_read;
    let mut pos: u64 = offset;
    let last_pos = full_read_size * id - readsize;

    let now = Instant::now();
    while pos <= last_pos {
        let read = unsafe {
            ReadFile(
                handle,
                buffer,
                readsize as DWORD,
                bytes_read_ptr,
                null_mut()
            )
        };
        pos += bytes_read as u64;
        if read == false { 
            println!("Thread {} encountered Error Code {}", id, last_error());
            break;
        }
    }
    let elapsed_time = now.elapsed();
    println!("Thread {} took {} seconds to finish", id, elapsed_time.as_secs());
    unsafe {
        CloseHandle(handle);
    }
    senderr.send(format!("finished|{}", id)).unwrap();
}

// Conduct threaded I/O operataion
// fn threaded_io(senderr: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, size: u64, io_size: u64, sector_size: u64, io_type: char) {
    
// }

// Calculate overall size of physical disk and I/O size
fn calculate_disk_info(disk_number: u8) -> (u64, u64, u64) {
    let result: Result<PhysicalDrive, String> = PhysicalDrive::open(disk_number);
    let parsed_result: PhysicalDrive = result.expect("Error opening physical disk");
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sectors = disk_geometry.sectors();
    let size = disk_geometry.size();
    let sector_size = size / sectors;
    let io_size = calculate_io_size(sector_size, MEGABYTE);
    return (size, io_size, sector_size);
}

// Calculate and return nearest number that is a multiple of a given other number
fn calculate_io_size(multiple: u64, base: u64) -> u64 {
    let remainder = base % multiple;
    if remainder == 0 {
        return base.into();
    }
    return (base + multiple - remainder).into();
}


// Calculate and return 
// fn calculate_nearest_multiple(number: u64, multiple: u64) -> u64 {
//     let result: u64 = ((number + multiple/2) / multiple) * multiple;
//     return result;
// }