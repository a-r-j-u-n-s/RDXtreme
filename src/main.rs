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
            .short('b')
            .long("buffer")
            .takes_value(true)
            .help("buffer size (in MB)"))
        .arg(Arg::new("use-groups")
            .long("use-groups")
            .takes_value(false))
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
    let mut multiple_groups: bool = false;
    let io_type: char;      // Identifier for opening handle and conducting IO
    if args.is_present("threads") {
        threads = args.value_of("threads").unwrap().parse().expect("Thread count must be a positive integer");
    }
    if args.is_present("use-groups") {
        multiple_groups = true;
    }
    if args.is_present("pattern") {
        pattern_str = args.value_of("pattern").unwrap().parse().expect("Pattern must be a valid string");
        compare_pattern = true;
    }
    if args.is_present("buffer") {
        let buffer_size: u64 = args.value_of("buffer").unwrap().parse().expect("IO size must be a valid string");
        io_size = buffer_size * MEGABYTE;
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
        let sen_clone: Sender<String> = sender.clone();
        thread::spawn(move || {
            let processor_groups: Vec<GROUP_AFFINITY> = get_proc_groups().unwrap();
            if multiple_groups {
                set_thread_group(processor_groups[threads as usize / num_cores]);   // Use multiple processor groups
                // println!("Thread {} at Group {}, Core {}", threads, processor_groups[threads as usize / num_cores].group, get_thread_affinity().unwrap()[0]);
            } else {
                set_thread_group(processor_groups[0]);      // Use first group with round robin approach if threads exceed core count
            }
            let affinity: Vec<usize> = vec![(threads % num_cores as u64) as usize; 1];      // Wrap threads around 
            let _ = set_thread_affinity(affinity);      // Pin thread to single CPU core
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
    // Different parameters needed for write/read handles
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
fn thread_io(sender: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, io_size: u64, limit: u64, io_type: char, pattern: u64) {
    let full_io_size: u64 = limit / num_threads;
    let path: String = format_drive_num(disk_number);
    let handle: Foundation::HANDLE = open_handle(&path, io_type).unwrap();

    // Set up FilePointer to start at offset based on thread number
    let mut offset = (id - 1) * full_io_size;

    // Set up data pattern
    let pattern_data: Vec<u64> = vec![pattern; io_size as usize / std::mem::size_of::<u64>()];

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
        // Set up references for write buffer and copy pattern data into buffer 
        let write_buffer_ptr_raw: *mut [u64] = std::ptr::slice_from_raw_parts_mut(buffer, io_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
        let write_buf: &mut [u64];
        unsafe {
            let buf_ptr: *mut [u64] = write_buffer_ptr_raw as *mut [u64];
            write_buf = &mut *buf_ptr;
            write_buf.copy_from_slice(&pattern_data);
        }
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
    let mut pattern_data: Vec<u64> = vec![pattern; io_size as usize / std::mem::size_of::<u64>()];

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
            io_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    // Set up references for write buffer and copy pattern data into buffer 
    let write_buffer_ptr_raw: *mut [u64] = std::ptr::slice_from_raw_parts_mut(write_buffer, io_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
    let write_buf: &mut [u64];
    unsafe {
        let buf_ptr: *mut [u64] = write_buffer_ptr_raw as *mut [u64];
        write_buf = &mut *buf_ptr;
        write_buf.copy_from_slice(&pattern_data);
    }
    
    let read_buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            io_size as usize,
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

    // Set up raw pointer and reference for read buffer
    let mut read_buffer_ptr_raw: *mut [u64];
    let mut read_buf: &mut [u64];

    // Full write
    while pos <= last_pos as u64 {

        // Write to drive
        let write = unsafe {
            FileSystem::WriteFile(
                handle,
                write_buffer,
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
    let mut iterations = 0;

    while iterations < 64 {
        // Shift pattern and modify write buffer
        original_pattern = pattern;
        pattern = bit_shift(pattern, 1);
        pattern_data = vec![pattern; io_size as usize / std::mem::size_of::<u64>()];
        write_buf.copy_from_slice(&pattern_data);

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
                    io_size as DWORD,
                    bytes_completed_ptr,
                    null_mut()
                )
            };

            // Retrieve data from read buffer for comparison
            read_buffer_ptr_raw = std::ptr::slice_from_raw_parts_mut(read_buffer, io_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
            unsafe {
                let buf_ptr: *mut [u64] = read_buffer_ptr_raw as *mut [u64];
                read_buf = &mut *buf_ptr;
            }

            // Compare read buffer to pattern
            received = read_buf[0];
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

            // Write shifted pattern to same LBA
            let write = unsafe {
                FileSystem::WriteFile(
                    handle,
                    write_buffer,
                    io_size as DWORD,
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


// Adapted from Andrew Adriance's Mempoke
#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
struct GROUP_AFFINITY {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

fn get_proc_groups() -> Option<Vec<GROUP_AFFINITY>> {
    use std::mem;
    use std::slice;

    #[allow(non_upper_case_globals)]
    const RelationProcessorCore: u32 = 0;

    #[repr(C)]
    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    struct PROCESSOR_RELATIONSHIP {
        flags: u8,
        efficiency_class: u8,
        reserved: [u8; 20],
        group_count: u16,
        group_mask_tenative: [GROUP_AFFINITY; 1],
    }

    #[repr(C)]
    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
        relationship: u32,
        size: u32,
        processor: PROCESSOR_RELATIONSHIP,
    }

    extern "system" {
        fn GetLogicalProcessorInformationEx(
            relationship: u32,
            data: *mut u8,
            length: &mut u32,
        ) -> bool;
    }

    // First we need to determine how much space to reserve.

    // The required size of the buffer, in bytes.
    let mut needed_size = 0;

    unsafe {
        GetLogicalProcessorInformationEx(RelationProcessorCore, null_mut(), &mut needed_size);
    }

    // Could be 0, or some other bogus size.
    if needed_size == 0 {
        return None;
    }

    // Allocate memory where we will store the processor info.
    let mut buffer: Vec<u8> = vec![0 as u8; needed_size as usize];

    unsafe {
        let result: bool = GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            buffer.as_mut_ptr(),
            &mut needed_size,
        );

        if result == false {
            return None;
        }
    }

    let mut affinity_list = Vec::<GROUP_AFFINITY>::new();
    let mut group_list = Vec::<u16>::new();

    let mut byte_offset: usize = 0;
    while byte_offset < needed_size as usize {
        unsafe {
            // interpret this byte-array as SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX struct
            let part_ptr_raw: *const u8 = buffer.as_ptr().offset(byte_offset as isize);
            let part_ptr: *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX =
                mem::transmute::<*const u8, *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                    part_ptr_raw,
                );
            let part: &SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX = &*part_ptr;

            // we are only interested in RelationProcessorCore information and hence
            // we have requested only for this kind of data (so we should not see other types of data)
            if part.relationship == RelationProcessorCore {
                // the number of GROUP_AFFINITY structs in the array will be specified in the 'groupCount'
                // we tenatively use the first element to get the pointer to it and reinterpret the
                // entire slice with the groupCount
                let groupmasks_slice: &[GROUP_AFFINITY] = slice::from_raw_parts(
                    part.processor.group_mask_tenative.as_ptr(),
                    part.processor.group_count as usize,
                );

                for affinity in groupmasks_slice {
                    if !group_list.contains(&affinity.group) {
                        affinity_list.push(*affinity);
                        group_list.push(affinity.group);
                    }
                }
            }

            // set the pointer to the next part as indicated by the size of this part
            byte_offset += part.size as usize;
        }
    }

    Some(affinity_list)
}

fn set_thread_group(group: GROUP_AFFINITY) {
    extern "system" {
        fn GetCurrentThread() -> LPVOID;
        fn SetThreadGroupAffinity(
            thread_handle: LPVOID,
            group_affinity: *mut GROUP_AFFINITY,
            previous_affinity: *mut u8,
        ) -> bool;
    }

    unsafe {
        SetThreadGroupAffinity(GetCurrentThread(), &mut group.clone(), null_mut());
    }
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
