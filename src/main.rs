use windows_drives::{drive::{PhysicalDrive, DiskGeometry}, win32};
use windows::{core::PCWSTR, Win32::{Storage::FileSystem, Foundation, System::{Ioctl, IO::DeviceIoControl}}};
use sysinfo::SystemExt;
use powershell_script;
use clap::Arg;
use std::{time::Instant, mem::{size_of, drop}, ptr::{null_mut, null}, process::exit, thread, string::String, sync::mpsc::{channel, Sender, Receiver}};
use winapi::{shared::minwindef::{DWORD, LPVOID}, um::{fileapi::OPEN_EXISTING, winbase::FILE_FLAG_NO_BUFFERING, winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE}, memoryapi::{VirtualAlloc, VirtualFree}}};
use affinity::*;
use std::num::ParseIntError;

// TODO: FIX COMPARE IO SIZE, MAKE IT HEAP ALLOCATED AND FUNCTION THE SAME WAY AS IT DOES FOR NORMAL IO

// Sector aligned constants
const MEGABYTE: u64 = 1048576;
const GIGABYTE: u64 = 1073741824;
const PAGE_SIZE: u64 = 4096;
const COMPARE_IO_SIZE: usize = 258048/2;        // IO size to use specifically for data comparisons

const NVME_MAX_LOG_SIZE: u64 = 0x1000;

fn main() {
    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    // CLI arguments
    let args = clap::App::new("Storage IO Test Tool")
        .version("v1.1.0")
        .author("Arjun Srivastava, Microsoft CHIE - ASE")
        .about("CLI to analyze and conduct multithreaded read/write IO operations and data comparisons on single-partition physical disks")
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
        .arg(Arg::new("limit (GB)")
            .short('g')
            .long("limitgb")
            .takes_value(true)
            .help("Limit (in GB) I/O size for read/write operation"))
        .arg(Arg::new("limit (MB)")
            .short('m')
            .long("limitmb")
            .takes_value(true)
            .help("Limit (in MB) I/O size for read/write operation"))
        .arg(Arg::new("pattern")
            .short('p')
            .long("pattern")
            .takes_value(true)
            .help("Data pattern to write to drive"))
        .arg(Arg::new("io")
            .short('i')
            .long("io")
            .takes_value(true)
            .help("IO size (in MB)"))
        .arg(Arg::new("controller")
            .short('c')
            .long("controller")
            .takes_value(true)
            .help("Display controller information for NVMe device"))
        .arg(Arg::new("namespace")
            .short('n')
            .long("namespace")
            .takes_value(true)
            .help("Display namespace information for NVMe device"))
        .get_matches();

    let partitions: u8;
    let mut pattern_str: String = String::from("0123456789abcdef");     // Default 64-bit pattern for conducting I/O data comparisons
    let pattern: u64;
    let mut compare_pattern: bool = false;
    let disk_number: u8;
    let io_size: u64;
    let mut threads: u64 = 1;
    let io_type: char;      // Identifier for opening handle and conducting IO
    if args.is_present("threads") {
        threads = args.value_of("threads").unwrap().parse().expect("Thread count must be a positive integer");
    }
    if args.is_present("pattern") {
        pattern_str = args.value_of("pattern").unwrap().parse().expect("Pattern must be a valid string");
        compare_pattern = true;
    }
    if args.is_present("io") {
        let io: u64 = args.value_of("io").unwrap().parse().expect("IO size must be a valid string");
        io_size = io * MEGABYTE;
    } else {
        io_size = MEGABYTE;
    }
    if args.is_present("read") {
        disk_number = args.value_of("read").unwrap().parse().expect("Disk number must be a valid integer");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            println!("Cannot conduct read IO operations on disk with multiple partitions, exiting...");
            exit(1);
        }
        io_type = 'r';
    } else if args.is_present("write") {
        disk_number = args.value_of("write").unwrap().parse().expect("Disk number must be a valid integer");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            println!("Cannot conduct write IO operations on disk with multiple partitions, exiting...");
            exit(1);
        }
        io_type = 'w';
    } else {
        // TODO: Get Identify Controller
        if args.is_present("controller") {
            disk_number = args.value_of("controller").unwrap().parse().expect("Disk number must be a valid integer!");
            let path = format_drive_num(disk_number);
            let handle: Foundation::HANDLE = open_handle(&path, 'r').unwrap();
            id_controller(handle);
            return;

        // TODO: Get Identify Namespace

        // TODO: Get Firmware Info
        }

        println!("Please specify an IO operation (--help for more information)");
        exit(0);
    }

    // Threading logic to handle reads/writes
    let num_threads = threads;
    let (sender, receiver): (Sender<String>, Receiver<String>) = channel();
    let (size, io_size, sector_size) = calculate_disk_info(disk_number, io_size);
    let mut limit = size;
    if args.is_present("limit (GB)") {
        limit = args.value_of("limit (GB)").unwrap().parse().expect("I/O MB limit must be a valid integer");
        limit *= GIGABYTE;
    } else if args.is_present("limit (MB)") {
        limit = args.value_of("limit (MB)").unwrap().parse().expect("I/O GB limit must be a valid integer");
        limit *= MEGABYTE;
    }
    
    println!("Disk {} size: {} bytes", disk_number, size);
    let num_cores = get_core_num();     // CPU cores in the current processor group
    pattern = parse_hex(&pattern_str).unwrap();
    while threads != 0 {
        let sen_clone = sender.clone();
        thread::spawn(move || {
            // Pin thread to single CPU core in first processor group
            let affinity: Vec<usize> = vec![(threads % num_cores as u64) as usize; 1];
            let _ = set_thread_affinity(affinity);
            // println!("Thread {} at Core: {}", threads, get_thread_affinity().unwrap()[0]);  // For debugging purposes 
            if compare_pattern {
                thread_data_pattern_io(sen_clone, num_threads, threads.clone(), disk_number, pattern, limit, sector_size, io_size);
            } else {
                thread_io(sen_clone, disk_number, num_threads, threads.clone(), io_size, limit, io_type, pattern);
            }
        });
        threads -= 1;
    }

    // Drop sender to avoid infinite loop
    drop(sender);

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


// Leverage Win32 to open a physical drive handle for reads/writes
fn open_handle(path: &str, handle_type: char) -> Result<Foundation::HANDLE, String> {
    let path = win32::win32_string(&path);
    let handle_template = Foundation::HANDLE(0);    // Generic hTemplate needed for CreateFileW
    let path_ptr: PCWSTR = PCWSTR(path.as_ptr() as *const u16);
    let handle: Foundation::HANDLE;
    if handle_type == 'w' {
        handle = unsafe {
            FileSystem::CreateFileW(
                path_ptr,
                FileSystem::FILE_ACCESS_FLAGS(GENERIC_WRITE | GENERIC_READ),
                FileSystem::FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
                null(),     // Security attributes not needed
                FileSystem::FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                FileSystem::FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_NO_BUFFERING),
                handle_template,
            ).unwrap()
        };
    } else {
        handle = unsafe {
            FileSystem::CreateFileW(
                path_ptr,
                FileSystem::FILE_ACCESS_FLAGS(GENERIC_READ),
                FileSystem::FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
                null(),     // Security attributes not needed
                FileSystem::FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                FileSystem::FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_NO_BUFFERING),
                handle_template,
            ).unwrap()
        }
    }
    if handle == Foundation::INVALID_HANDLE_VALUE {
        let err = win32::last_error();
        Err(match err {
            2 => "could not open handle because the device was not found".to_string(),
            5 => "could not open handle because access was denied - enable administrator privileges".to_string(),
            _ => format!("got invalid handle: error code {:#08x}", err)
        })
    } else {
        Ok(handle)
    }
}

// Conduct threaded IO operation (read/write)
fn thread_io(sender: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, io_size: u64, limit: u64, io_type: char, _pattern: u64) {
    let full_io_size: u64 = limit / num_threads;
    let path: String = format_drive_num(disk_number);
    let handle: Foundation::HANDLE = open_handle(&path, io_type).unwrap();

    // Set up FilePointer to start at offset based on thread number
    let mut offset = (id - 1) * full_io_size;

    // Set up data pattern
    // let pattern_data: Vec<u64> = vec![pattern; COMPARE_IO_SIZE];

    // Reset offset if not an even multiple of page size (4k bytes)
    offset = calculate_nearest_multiple(PAGE_SIZE, offset);

    let mut initialization_offset = 0;
    if io_type == 'w' && id == 1 {   // Add 1 MB offset for the first thread to avoid uninitializing drive
        initialization_offset += MEGABYTE;
    }

    let _pointer = unsafe {
        FileSystem::SetFilePointerEx(
            handle,
            (offset + initialization_offset) as i64,
            null_mut(),
            FileSystem::FILE_BEGIN
        )
    };

    // Allocate sector-aligned buffer with Win32 VirtualAlloc
    let buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            io_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    

    let mut bytes_completed: u32 = 0;
    let bytes_completed_ptr: *mut u32 = &mut bytes_completed;
    let mut pos: u64 = offset;
    let last_pos: u64 = full_io_size * id - io_size - initialization_offset;

    if io_type == 'w' {
        let now = Instant::now();
        while pos <= last_pos {
            let write = unsafe {
                FileSystem::WriteFile(
                    handle,
                    buffer,
                    io_size as DWORD,
                    bytes_completed_ptr,
                    null_mut()
                )
            };
            pos += bytes_completed as u64;
            if write == false {
                println!("Thread {} encountered Error Code {}", id, win32::last_error());
                break;
            }
    }
        let elapsed_time = now.elapsed();
        println!("Thread {} took {} seconds to finish writing", id, elapsed_time.as_secs());
    } else if io_type == 'r' {
        let now = Instant::now();
        while pos <= last_pos {
            let read = unsafe {
                FileSystem::ReadFile(
                    handle,
                    buffer,
                    io_size as DWORD,
                    bytes_completed_ptr,
                    null_mut()
                )
            };
            pos += bytes_completed as u64;
            if read == false { 
                println!("Thread {} encountered Error Code {}", id, win32::last_error());
                break;
            }
        }
        let elapsed_time = now.elapsed();
        println!("Thread {} took {} seconds to finish reading", id, elapsed_time.as_secs());
    }

    unsafe {
        // Clean up resources
        VirtualFree(buffer, 0, MEM_RELEASE);
        Foundation::CloseHandle(handle);
    }
    sender.send(format!("finished|{}", id)).unwrap();
}


// Multithreaded write/compare data patterns
fn thread_data_pattern_io(sender: std::sync::mpsc::Sender<String>, num_threads: u64, id: u64, disk_number: u8, mut original_pattern: u64, size: u64, _sector_size: u64, io_size: u64) {
    let mut pattern = original_pattern;     // For data comparisons
    let full_io_size = size / num_threads;
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'w').unwrap();

    // Set up FilePointer to start at offset based on thread number
    let mut offset = (id - 1) * full_io_size;

    // Reset offset if not an even multiple of page size (4k bytes)
    offset = calculate_nearest_multiple(PAGE_SIZE, offset);

    // Set up data pattern
    let mut pattern_data: Vec<u64> = vec![pattern; COMPARE_IO_SIZE];

    let mut initialization_offset = 0;
    if id == 1 {   // Add 1 MB offset for the first thread to avoid uninitializing drive
        initialization_offset += MEGABYTE;
    }

    let mut _pointer = unsafe {
        FileSystem::SetFilePointerEx(
            handle,
            (offset + initialization_offset) as i64,
            null_mut(),
            FileSystem::FILE_BEGIN
        )
    };

    // Allocate sector-aligned buffers with Win32 VirtualAlloc
    let write_buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            COMPARE_IO_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    // Dumb but effective (for now) method to move pattern into sector-aligned buffer
    let buf: *mut [u64; COMPARE_IO_SIZE] = write_buffer as *mut [u64; COMPARE_IO_SIZE];
    let mut buf_local: [u64; COMPARE_IO_SIZE] = unsafe{*buf};
    buf_local.copy_from_slice(&pattern_data);       // Copy pattern to local write buffer
    let write_buffer_ptr: LPVOID = &mut buf_local as *mut _ as LPVOID;

    let read_buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            COMPARE_IO_SIZE as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    // I/O logistics
    let mut bytes_completed: u32 = 0;
    let bytes_completed_ptr: *mut u32 = &mut bytes_completed;
    let mut pos: u64 = offset;
    let last_pos: u64 = full_io_size * id - io_size - initialization_offset;

    let mut received: u64;

    // Raw pointer for read buffer
    let mut read_buffer_ptr: *mut [u64; COMPARE_IO_SIZE];
    let mut read_buffer_local: [u64; COMPARE_IO_SIZE];

    // Full write
    while pos <= last_pos as u64 {

        // Write to drive
        let write = unsafe {
            FileSystem::WriteFile(
                handle,
                write_buffer_ptr,
                COMPARE_IO_SIZE as DWORD,
                bytes_completed_ptr,
                null_mut()
            )
        };

        pos += bytes_completed as u64;

        if write == false {
            println!("Thread {} encountered Error Code {}", id, win32::last_error());
            break;
        }
    }
    let mut iterations = 0;

    while iterations < 64 {
        // Shift pattern and modify write buffer
        original_pattern = pattern;
        pattern = bit_shift(pattern, 1);
        pattern_data = vec![pattern; COMPARE_IO_SIZE];
        buf_local.copy_from_slice(&pattern_data);

        // Reset position and move pointer back to initial offset to conduct read
        pos = offset;
        _pointer = unsafe {
            FileSystem::SetFilePointerEx(
                handle,
                (offset + initialization_offset) as i64,
                null_mut(),
                FileSystem::FILE_BEGIN
            )
        };

        // Full read/compare
        while pos <= last_pos {
            let read = unsafe {
                FileSystem::ReadFile(
                    handle,
                    read_buffer,
                    COMPARE_IO_SIZE as DWORD,
                    bytes_completed_ptr,
                    null_mut()
                )
            };

            // Move data from virtually allocated read buffer into local buffer for comparison
            read_buffer_ptr = read_buffer as *mut [u64; COMPARE_IO_SIZE];
            read_buffer_local = unsafe {*read_buffer_ptr};

            // Compare read buffer to pattern
            received = read_buffer_local[0];
            if received != original_pattern {
                println!(   
                    "Data mismatch at thread {}! Actual({:#018x}) vs Expected({:#018x})", id, received, original_pattern
                );
            }

            pos += bytes_completed as u64;
            if read == false {
                println!("Thread {} encountered Error Code {}", id, win32::last_error());
                break;
            }

            // Move pointer back to conduct read
            _pointer = unsafe {
                FileSystem::SetFilePointerEx(
                    handle,
                    (bytes_completed as i64 * -1) as i64,
                    null_mut(),
                    FileSystem::FILE_CURRENT
                )
            };

            let write = unsafe {
                FileSystem::WriteFile(
                    handle,
                    write_buffer_ptr,
                    COMPARE_IO_SIZE as DWORD,
                    bytes_completed_ptr,
                    null_mut()
                )
            };

            if write == false {
                println!("Thread {} encountered Error Code {}", id, win32::last_error());
                break;
            }
        }
        iterations += 1;
    }
    unsafe {
        // Clean up resources
        VirtualFree(read_buffer, 0, MEM_RELEASE);
        VirtualFree(write_buffer, 0, MEM_RELEASE);
        Foundation::CloseHandle(handle);
    }
    sender.send(format!("finished|{}", id)).unwrap();
}


// Calculate overall size of physical disk and I/O size
fn calculate_disk_info(disk_number: u8, iosize: u64) -> (u64, u64, u64) {
    let result: Result<PhysicalDrive, String> = PhysicalDrive::open(disk_number);
    let parsed_result: PhysicalDrive = result.expect("Error opening physical disk");
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sectors = disk_geometry.sectors();
    let size = disk_geometry.size();
    let sector_size = size / sectors;
    let io_size = calculate_nearest_multiple(sector_size, iosize);
    return (size, io_size, sector_size);
}


// Calculate and return nearest number to "base" that is a multiple of "multiple"
fn calculate_nearest_multiple(multiple: u64, base: u64) -> u64 {
    let remainder = base % multiple;
    if remainder == 0 {
        return base.into();
    }
    return (base + multiple - remainder).into();
}


// Format drive number for Win32 API
fn format_drive_num(drive_num: u8) -> String {
    return format!("\\\\.\\PhysicalDrive{}", drive_num);
}


fn bit_shift(data: u64, iterations: u64) -> u64 {
    let rotation = iterations % 16;        // Reset after each digit has been shifted once
    let bit_count = rotation * 4;
    data.rotate_right(bit_count.try_into().unwrap())
}


fn parse_hex(src: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(src, 16)
}

// TODO: Retrieve Identify Controller information 
#[allow(unused)]
fn id_controller(h_device: Foundation::HANDLE) {
    let status: u32;

    /*
    - Allocate a buffer that can contains both a STORAGE_PROPERTY_QUERY and a STORAGE_PROTOCOL_SPECIFIC_DATA structure.
    - Set the PropertyID field to StorageAdapterProtocolSpecificProperty or StorageDeviceProtocolSpecificProperty for a controller or device/namespace request, respectively.
    - Set the QueryType field to PropertyStandardQuery.
    - Fill the STORAGE_PROTOCOL_SPECIFIC_DATA structure with the desired values. The start of the STORAGE_PROTOCOL_SPECIFIC_DATA is the AdditionalParameters field of STORAGE_PROPERTY_QUERY.
    */

    // TODO: Need to change this to use Field Offset so that the STORAGE_PROTOCOL_SPECIFIC_DATA starts at the AdditionalParameters field
    let buffer_length: usize = size_of::<Ioctl::STORAGE_PROPERTY_QUERY>() + size_of::<Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA>() + NVME_MAX_LOG_SIZE as usize;
    let mut returned_length: u32 = 0;
    let returned_length_ptr: *mut u32 = &mut returned_length as *mut u32;

    // Allocate buffer
    let mut buffer = vec![0; buffer_length as usize];
    let buffer_ptr: LPVOID = &mut buffer as *mut _ as LPVOID;

    let query: *mut Ioctl::STORAGE_PROPERTY_QUERY = buffer_ptr as *mut Ioctl::STORAGE_PROPERTY_QUERY;
    let descriptor: *mut Ioctl::STORAGE_PROTOCOL_DATA_DESCRIPTOR = buffer_ptr as *mut Ioctl::STORAGE_PROTOCOL_DATA_DESCRIPTOR;
    let data: *mut Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA;

    // Set up input buffer for DeviceIoControl
    unsafe {
        (*query).PropertyId = Ioctl::StorageAdapterProtocolSpecificProperty;
        (*query).QueryType = Ioctl::PropertyStandardQuery;
        // (*query).AdditionalParameters as *mut STORAGE_PROTOCOL_SPECIFIC_DATA;

    }

    // Use box instead of vec?
    let boxed_query: Box<Ioctl::STORAGE_PROPERTY_QUERY> = Box::new(Ioctl::STORAGE_PROPERTY_QUERY {
        PropertyId: Ioctl::StorageAdapterProtocolSpecificProperty,
        QueryType: Ioctl::PropertyStandardQuery,
        AdditionalParameters: [1] 
    });

    let result: Foundation::BOOL = unsafe {
        DeviceIoControl(h_device,
                Ioctl::IOCTL_STORAGE_QUERY_PROPERTY,
                     buffer_ptr,
                  buffer_length as u32,
                    buffer_ptr,
                 buffer_length as u32,
                returned_length_ptr,
                   null_mut())
    };

    if !result.as_bool() || (returned_length == 0) {
        status = win32::last_error();
        println!("Get Identify Controller Data failed. Error Code {}", status);
        exit(1);
    }

}
