use windows_drives::{drive::{PhysicalDrive, DiskGeometry}, win32};
use windows::{core::PCWSTR, Win32::{Storage::FileSystem, Foundation, System::{Ioctl, IO::DeviceIoControl}}};
use sysinfo::SystemExt;
use powershell_script;
use clap::Arg;
use std::{time::Instant, mem::{size_of, drop}, ptr::{null_mut, null}, process::exit, thread, string::String, sync::mpsc::{channel, Sender, Receiver}, u32::MAX};
use winapi::{shared::minwindef::{DWORD, LPVOID}, um::{fileapi::OPEN_EXISTING, winbase::FILE_FLAG_NO_BUFFERING, winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE}, memoryapi::{VirtualAlloc, VirtualFree}}};
use affinity::*;
use std::num::ParseIntError;
use log::{debug, error, warn, info};
use json::{object, JsonValue};
use std::fs::{File, remove_file};
use std::io::prelude::*;
use rand::Rng;

// Sector aligned buffer size constants
const MEGABYTE: u64 = 1048576;
const GIGABYTE: u64 = 1073741824;
const PAGE_SIZE: u64 = 4096;
const INITIALIZATION_OFFSET: u64 = 4096;

const NVME_MAX_LOG_SIZE: u32 = 0x1000;

// Test Type
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Test {
    WriteOnly,
    MovingInversions,
    ReadCompare,
    RandomReads,
    RandomWriteCycle
}

// TODO: wrap virtualalloc in struct with drop, better memcpy comparisons, GET RID OF WRITEONLY DEFAULT

fn main() {
    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    // CLI arguments
    let args = clap::App::new("rdxtreme - Storage IO Test Tool")
        .version("v2.1.0")
        .author("Arjun Srivastava, Microsoft CHIE - ASE")
        .about("CLI to analyze and conduct multithreaded read/write IO operations and data comparison tests on single-partition physical disks")
        .arg(Arg::new("info")
            .long("info")
            .takes_value(false)
            .help("Print information about physical drives on your machine"))
        .arg(Arg::new("physical-disk")
            .short('p')
            .long("physical-disk")
            .takes_value(true)
            .help("Physical disk ID to run I/O operations on"))
        .arg(Arg::new("write")
            .short('w')
            .long("write")
            .takes_value(false)
            .help("Write mode"))
        .arg(Arg::new("threads")
            .short('t')
            .long("threads")
            .takes_value(true)
            .help("Number of threads to use"))
        .arg(Arg::new("read")
            .short('r')
            .long("read")
            .takes_value(false)
            .help("Read/compare mode"))
        .arg(Arg::new("time")
            .long("time")
            .takes_value(true)
            .help("Time (s) to run I/O test"))
        .arg(Arg::new("test")
            .long("test")
            .short('T')
            .takes_value(true)
            .help("Test case to run\nOptions:\n0. Any Pattern Full Write No Comparison - i*[>W] (default)\n1. Any Pattern 64 Bit Moving Inversions with Data Comparison - i*[>W 64*[>r,c,w~]]\n2. Any Pattern 64 Bit Write and Read/Compare - [>W i*[>r,c]]\n3. Any Pattern 64 Bit Write and Random Read/Compare - [>W i*[>rr,c,h,d]\n4. Any Pattern 64 Bit Random Write/Read/Compare - T*[>ww,r,c]"))
        .arg(Arg::new("no-compare")
            .short('n')
            .long("no-compare")
            .takes_value(false)
            .help("Disable data comparisons for tests"))
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
        .arg(Arg::new("hold")
            .short('h')
            .long("hold")
            .takes_value(true)
            .help("Time (s) to run each random read for (only for specific test cases)"))
        .arg(Arg::new("delay")
            .short('d')
            .long("delay")
            .takes_value(true)
            .help("Time (s) before running random reads again (only for specific test cases)"))
        .arg(Arg::new("pattern")
            .short('P')
            .long("pattern")
            .takes_value(true)
            .help("Data pattern to write to drive"))
        .arg(Arg::new("iterations")
            .short('i')
            .long("iterations")
            .takes_value(true)
            .help("Number of times to conduct I/O operation"))
        .arg(Arg::new("buffer")
            .short('b')
            .long("buffer")
            .takes_value(true)
            .help("Buffer size\nSupported sizes: 512b, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m"))
        .arg(Arg::new("use-groups")
            .long("use-groups")
            .takes_value(false)
            .help("Utilize multiple processor groups to increase performance"))
        .arg(Arg::new("debug")
            .long("debug")
            .takes_value(false)
            .help("Display debug information in log output"))
        .arg(Arg::new("controller")
            .short('C')
            .long("controller")
            .takes_value(false)
            .help("Display identify controller information for NVMe device"))
        .get_matches();

    let partitions: u8;
    let mut pattern_str: String = String::from("0123456789abcdef");     // Default 64-bit pattern for conducting I/O data comparisons
    let pattern: u64;
    let mut compare_pattern: bool = true;
    let disk_number: u8;
    let mut buffer_size: u64 = MEGABYTE;    // Defaulyt buffer size
    let mut buffer_size_str: &str = "1m";
    let mut threads: u64 = 1;
    let mut multiple_groups: bool = false;
    let io_type: char;      // Identifier for opening handle and conducting IO
    let mut log_type: &str = "info";
    let mut iterations: u64 = 1;    // Number of times to run I/O operations
    let mut id_json: JsonValue = json::JsonValue::new_array();
    let mut time: u64 = 0;
    let mut test: Test = Test::WriteOnly;
    let mut hold_time: u32 = 0;     // Time to run random read/compare
    let mut delay_time: u32 = 0;    // Time before starting next read/compare cycle

    // Set logging type
    if args.is_present("debug") {
        log_type = "debug"
    }
    // Set up logging
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_type));

    info!("Begin program");

    // Get disk information
    let get_physicaldisks_script = include_str!("get_physicaldisks.ps1");
    match powershell_script::run(get_physicaldisks_script) {
        Ok(output) => {
            let stdout = String::from(output.stdout().unwrap());
            parse_script(&stdout, &mut id_json);
            if args.is_present("info") {
                let serialized = json::stringify(id_json.clone());
                let mut file = File::create("disk_info.json").expect("Error encountered while creating file!");
                file.write_all(serialized.as_bytes()).expect("Error writing disk information to file");
                let ps = powershell_script::PsScriptBuilder::new()
                    .no_profile(true)
                    .non_interactive(true)
                    .hidden(false)
                    .print_commands(false)
                    .build();
                let output = ps.run(r#"
                    $DiskInfo = Get-Content ./disk_info.json | ConvertFrom-Json
                    foreach ($Disk in $DiskInfo) {
                        $DiskNumber = $Disk.DeviceId
                        [array]$Partitions = Get-Partition $DiskNumber
                        $Disk | Add-Member -MemberType NoteProperty -Name 'Partitions' -Value ($Partitions.count)
                    }
                    $Table = $DiskInfo | Format-Table 'DeviceId', 'FriendlyName', 'SerialNumber', 'MediaType', 'Partitions', 'Sector Size', 'Firmware Version'
                    Write-Output $Table
                "#).unwrap();
                println!("Physical Drive Information:\n{}", output.stdout().unwrap());
                let _result = remove_file("./disk_info.json").expect("Encountered error removing temporary JSON file for Disk Info");
            }
        }
        Err(e) => {
            error!("Error: {}", e);
        }
    }    

    if args.is_present("physical-disk") {
        disk_number = args.value_of("physical-disk").unwrap().parse().expect("Disk number must be a valid integer");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            error!("Cannot conduct IO operations on disk with multiple partitions, exiting...");
            exit(1);
        }
    } else {
        warn!("Must select a physical disk ID to conduct I/O operations. (--info for a list of your disks)");
        exit(0);
    }

    if args.is_present("controller") {
        let path = &format_drive_num(disk_number);
        let handle: Foundation::HANDLE = open_handle(path, 'w').unwrap();
        id_controller(handle);
    }

    if args.is_present("test") {
        let id: u8 = args.value_of("test").unwrap().parse().expect("Test ID must be a valid integer");
        test = select_test_type(id);
        io_type = 't';      // Test
    } else if args.is_present("write") {
        info!("Write mode");
        io_type = 'w';      // Write
    } else if args.is_present("read") {
        io_type = 'r';      // Read
        warn!("Read/compare mode, all write operations will be canceled");
    } else {
        warn!("Please specify an I/O operation OR test case (--help for more information)");
        exit(0);
    }

    if args.is_present("iterations") {
        iterations = args.value_of("iterations").unwrap().parse().expect("Number of iterations must be a positive integer");
        info!("Operations will loop {} times", iterations);
    }
    
    if args.is_present("threads") {
        threads = args.value_of("threads").unwrap().parse().expect("Thread count must be a positive integer");
    }
    if args.is_present("use-groups") {
        multiple_groups = true;
    }
    if args.is_present("pattern") {
        pattern_str = args.value_of("pattern").unwrap().parse().expect("Pattern must be a valid string");
        if pattern_str.len() > 16 {
            error!("Hexadecimal pattern must be 64-bit or smaller!");
            exit(1);
        }
    }
    if args.is_present("buffer") {
        buffer_size_str = args.value_of("buffer").unwrap();
        buffer_size = get_buffer_size(buffer_size_str);
        if buffer_size == 0 {
            exit(1);
        }
    }
    info!("Data pattern: {}{}", "0x", pattern_str);
    
    if args.is_present("no-compare") {
        compare_pattern = false;
        info!("Data comparisons disabled");
    }    

    // Threading logic to handle reads/writes
    let num_threads = threads;
    let (sender, receiver): (Sender<String>, Receiver<String>) = channel();
    let (size, mut buffer_size, sector_size) = calculate_disk_info(disk_number, buffer_size);

    let mut limit = size;
    if args.is_present("limit (GB)") {
        limit = args.value_of("limit (GB)").unwrap().parse().expect("I/O MB limit must be a valid integer");
        limit *= GIGABYTE;
    } else if args.is_present("limit (MB)") {
        limit = args.value_of("limit (MB)").unwrap().parse().expect("I/O GB limit must be a valid integer");
        limit *= MEGABYTE;
    }
    if limit > size {
        warn!("Requested limit is too large, truncating to the full size of the drive ({} bytes)", size);
    }

    if args.is_present("hold") {
        hold_time = args.value_of("hold").unwrap().parse().expect("Hold time valid integer");
    }
    if args.is_present("delay") {
        delay_time = args.value_of("delay").unwrap().parse().expect("Delay time must be a valid integer");
    }

    // Reset buffer size if necessary to avoid race conditions during threaded operations
    if threads * buffer_size > limit {
        buffer_size = calculate_nearest_multiple(PAGE_SIZE, limit / threads);
        warn!("Reducing I/O operation size to {} bytes to accomodate thread count", buffer_size);
    }
    
    info!("Disk {} Information:", disk_number);
    for a in 0..id_json.len() {
        let device: &JsonValue = &id_json[a];

        let id: &JsonValue = &device["DeviceId"];
        let id_str: String = String::from(id.as_str().unwrap());
        let disk_num_str: String = disk_number.to_string();
        if id_str == disk_num_str {
            info!("Friendly Name: {}", &device["FriendlyName"]);
            info!("Serial Number: {}", &device["SerialNumber"]);
            info!("Size: {} bytes", size);
            info!("Media Type: {}", &device["MediaType"]);
            info!("Firmware Version: {}", &device["Firmware Version"]);
            break;
        }
    }    
    info!("Buffer size: {} ({} bytes)", buffer_size_str, buffer_size);
    info!("Thread count: {}", threads);

    if multiple_groups {
        info!("Program will utilze multiple processor groups");
    } else {
        info!("Program will utilize the first processor group only");
    }
    if args.is_present("time") {
        time = args.value_of("time").unwrap().parse().expect("time must be a valid integer");
        info!("Program will stop after {} seconds", time);
    }

    // Require hold time to be set to conduct Random Reads/Compare test
    if test == Test::RandomReads && hold_time <= 0 {
        error!("Must set time limit for random reads with `-h--hold` (--help for more info)");
        return;
    }

    // Require time limit to be set if running Random Write/Read/Compare Cycle test
    if test == Test::RandomWriteCycle && time <= 0 {
        warn!("Random Write/Read/Compare test will run indefinitely and must be terminated with Ctrl^C");
        time = MAX as u64;
    }

    let num_cores = get_core_num();     // CPU cores in the current processor group
    pattern = parse_hex(&pattern_str).unwrap();
    while threads != 0 {
        let sen_clone: Sender<String> = sender.clone();
        thread::spawn(move || {
            let processor_groups: Vec<GROUP_AFFINITY> = get_proc_groups().unwrap();
            if multiple_groups {
                set_thread_group(processor_groups[threads as usize / num_cores]);   // Use multiple processor groups
            } else {
                set_thread_group(processor_groups[0]);      // Use first group with round robin approach if threads exceed core count
            }
            let affinity: Vec<usize> = vec![(threads % num_cores as u64) as usize; 1];      // Wrap threads around 
            let _ = set_thread_affinity(affinity);      // Pin thread to single CPU core
            debug!("Thread {} at Group {}, Core {}", threads, processor_groups[threads as usize / num_cores].group, get_thread_affinity().unwrap()[0]);
            
            // Run chosen I/O operation
            if (io_type == 'r' && !compare_pattern) || io_type == 'w' {
                conduct_io_operation(sen_clone, disk_number, num_threads, threads.clone(), buffer_size, limit, io_type, pattern, iterations, time);
            } else {
                conduct_data_comparison(sen_clone, num_threads, threads.clone(), disk_number, pattern, limit, sector_size, buffer_size, iterations, time, test, compare_pattern, io_type, hold_time, delay_time);
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
                debug!("[Thread {}]: Status: {}", isplit.clone().last().unwrap(), isplit.clone().next().unwrap());
                threads_clone -= 1;
                if threads_clone == 0 {
                    info!("All pending I/O operations finished");
                    break;
                }
            }
        }
    });
    receiver_thread.join().unwrap();
    info!("All pending I/O operations finished");
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
fn conduct_io_operation(sender: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, buffer_size: u64, size: u64, io_type: char, pattern: u64, loops: u64, time: u64) {
    let mut initialization_offset = 0;
    if io_type == 'w' {   // Add 4 KB offset to all operations to avoid overwriting drive
        initialization_offset = INITIALIZATION_OFFSET;
    }
    let local_limit = calculate_nearest_multiple(PAGE_SIZE, size / num_threads);     // Align full IO size
    let path: String = format_drive_num(disk_number);
    let handle: Foundation::HANDLE = open_handle(&path, io_type).unwrap();
    let mut now: Instant;
    let mut elapsed_time;

    // Set up FilePointer to start at offset based on thread number
    let mut offset = (id - 1) * local_limit;

    // Set up data pattern
    let pattern_data: Vec<u64> = vec![pattern; buffer_size as usize / std::mem::size_of::<u64>()];

    // Reset offset if not an even multiple of page size (4k bytes)
    offset = calculate_nearest_multiple(PAGE_SIZE, offset);

     // Allocate sector-aligned buffer with Win32 VirtualAlloc
     let buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            buffer_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    let mut i: u64 = 0;
    while i < loops {
        let _pointer = unsafe {
            FileSystem::SetFilePointerEx(
                handle,
                (offset + initialization_offset) as i64,
                null_mut(),
                FileSystem::FILE_BEGIN
            )
        };
        
        // I/O logistics
        let mut bytes_completed: u32 = 0;
        let bytes_completed_ptr: *mut u32 = &mut bytes_completed;
        let mut pos: u64 = offset;
        let last_pos: u64 = local_limit * id - buffer_size;

        if io_type == 'w' {
            // Set up references for write buffer and copy pattern data into buffer 
            let write_buffer_ptr_raw: *mut [u64] = std::ptr::slice_from_raw_parts_mut(buffer, buffer_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
            let write_buf: &mut [u64];

            // Dereference buffer to add pattern data
            unsafe {
                let buf_ptr: *mut [u64] = write_buffer_ptr_raw as *mut [u64];
                write_buf = &mut *buf_ptr;
                write_buf.copy_from_slice(&pattern_data);
            }
            now = Instant::now();
            while pos <= last_pos {
                let write = unsafe {
                    FileSystem::WriteFile(
                        handle,
                        buffer,
                        buffer_size as DWORD,
                        bytes_completed_ptr,
                        null_mut()
                    )
                };
                pos += bytes_completed as u64;
                if write == false {
                    error!("Thread {} encountered Error Code {}", id, win32::last_error());
                    break;
                }
                if time > 0 && now.elapsed().as_secs() > time {
                    break;
                }
        }
            elapsed_time = now.elapsed();
            debug!("Thread {} took {} seconds to finish writing", id, elapsed_time.as_secs());
        } else if io_type == 'r' {
            now = Instant::now();
            while pos <= last_pos {
                let read = unsafe {
                    FileSystem::ReadFile(
                        handle,
                        buffer,
                        buffer_size as DWORD,
                        bytes_completed_ptr,
                        null_mut()
                    )
                };
                pos += bytes_completed as u64;
                if read == false { 
                    error!("Thread {} encountered Error Code {}", id, win32::last_error());
                    break;
                }
                if time > 0 && now.elapsed().as_secs() > time {
                    break;
                }
            }
            elapsed_time = now.elapsed();
            debug!("Thread {} took {} seconds to finish reading", id, elapsed_time.as_secs());
        }
        i += 1;
    }
    unsafe {
        // Clean up resources
        VirtualFree(buffer, 0, MEM_RELEASE);
        Foundation::CloseHandle(handle);
    }
    sender.send(format!("finished|{}", id)).unwrap();
}


// Multithreaded write/compare data patterns
fn conduct_data_comparison(sender: std::sync::mpsc::Sender<String>, num_threads: u64, id: u64, disk_number: u8, mut original_pattern: u64, size: u64, _sector_size: u64, buffer_size: u64, loops: u64, time: u64, test: Test, compare_pattern: bool, io_type: char, hold_time: u32, delay_time: u32) {
    let mut pattern = original_pattern;     // For data comparisons
    let local_limit = calculate_nearest_multiple(PAGE_SIZE, size / num_threads);     // Align full IO size
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'w').unwrap();

    // Set up FilePointer to start at offset based on thread number
    let mut offset = (id - 1) * local_limit;

    // Reset offset if not an even multiple of page size (4k bytes)
    offset = calculate_nearest_multiple(PAGE_SIZE, offset);

    // Set up data pattern
    let mut pattern_data: Vec<u64> = vec![pattern; buffer_size as usize / std::mem::size_of::<u64>()];

    // Allocate sector-aligned buffers with Win32 VirtualAlloc
    let write_buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            buffer_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    // Set up references for write buffer and copy pattern data into buffer 
    let write_buffer_ptr_raw: *mut [u64] = std::ptr::slice_from_raw_parts_mut(write_buffer, buffer_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
    let write_buf: &mut [u64];
    unsafe {
        let buf_ptr: *mut [u64] = write_buffer_ptr_raw as *mut [u64];
        write_buf = &mut *buf_ptr;
        write_buf.copy_from_slice(&pattern_data);
    }
    
    let read_buffer: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            buffer_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    let mut i: u64 = 0;
    let now = Instant::now();

    while i < loops {
        // Move file pointer based on calculated byte offset
        let mut _pointer = unsafe {
            FileSystem::SetFilePointerEx(
                handle,
                (offset + INITIALIZATION_OFFSET) as i64,
                null_mut(),
                FileSystem::FILE_BEGIN
            )
        };

        // I/O logistics
        let mut bytes_completed: u32 = 0;
        let bytes_completed_ptr: *mut u32 = &mut bytes_completed;
        let mut pos: u64 = offset;
        let last_pos: u64 = local_limit * id - buffer_size;
        let mut received: u64;

        // Maximum integer that can be used as a multiplier to read from a random offset within this thread's range
        let random_multiplier_range: u64 = local_limit / buffer_size;

        // Set up raw pointer and reference for read buffer
        let mut read_buffer_ptr_raw: *mut [u64];
        let mut read_buf: &mut [u64];

        // Random Write/Read/Compare Cycle
        if test == Test::RandomWriteCycle {
            let now = Instant::now();
            while now.elapsed().as_secs() < time {
                // Generate random multiplier
                let random_multiplier = rand::thread_rng().gen_range(0..random_multiplier_range);
                let random_offset = random_multiplier * buffer_size;

                // Move file pointer to random locations to conduct Random Reads/Compare test
                _pointer = unsafe {
                    FileSystem::SetFilePointerEx(
                        handle,
                        (offset + INITIALIZATION_OFFSET + random_offset) as i64,
                        null_mut(),
                        FileSystem::FILE_BEGIN
                    )
                };

                // Write to random location
                let write = unsafe {
                    FileSystem::WriteFile(
                        handle,
                        write_buffer,
                        buffer_size as DWORD,
                        bytes_completed_ptr,
                        null_mut()
                    )
                };

                if write == false {
                    error!("Thread {} encountered Error Code {}", id, win32::last_error());
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
                
                // Read from same location
                let read = unsafe {
                    FileSystem::ReadFile(
                        handle,
                        read_buffer,
                        buffer_size as DWORD,
                        bytes_completed_ptr,
                        null_mut()
                    )
                };

                if read == false {
                    error!("Thread {} encountered Error Code {}", id, win32::last_error());
                    break;
                }

                if compare_pattern {
                    // Retrieve data from read buffer for comparison
                    read_buffer_ptr_raw = std::ptr::slice_from_raw_parts_mut(read_buffer, buffer_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
                    unsafe {
                        let buf_ptr: *mut [u64] = read_buffer_ptr_raw as *mut [u64];
                        read_buf = &mut *buf_ptr;
                    }

                    // Compare read buffer to pattern
                    received = read_buf[0];
                    if received != original_pattern {
                        error!(   
                            "Data corruption at offset {}! Thread {}. Actual({:#018x}) vs Expected({:#018x})", pos, id, received, original_pattern
                        );
                    }
                    
                }
            }
            break;
        }

        // Full write
        if io_type != 'r' {
            while pos <= last_pos as u64 {
                // Write to drive
                let write = unsafe {
                    FileSystem::WriteFile(
                        handle,
                        write_buffer,
                        buffer_size as DWORD,
                        bytes_completed_ptr,
                        null_mut()
                    )
                };

                pos += bytes_completed as u64;

                if write == false {
                    error!("Thread {} encountered Error Code {}", id, win32::last_error());
                    break;
                }
                if time > 0 && now.elapsed().as_secs() > time {
                    break;
                }
            }
        }
        let mut iterations: u64 = 0;
        let runs: u64;
        if test == Test::MovingInversions {
            runs = 64;      // We want the 64-bit pattern to be fully shifted for this test, so we run the bit shift 64 times
        } else {
            runs = loops;       // If we are not running a Moving Inversion test, loop the read/compares according to the iterations parameter
        }
    
        // Conduct specific I/O tests
        while iterations < runs {
            if test == Test::MovingInversions {      // Shift pattern and modify write buffer
                original_pattern = pattern;
                pattern = bit_shift(pattern, 1);
                pattern_data = vec![pattern; buffer_size as usize / std::mem::size_of::<u64>()];
                write_buf.copy_from_slice(&pattern_data);
            }
            
            // Reset position and move pointer back to initial offset to conduct read
            pos = offset;
            _pointer = unsafe {
                FileSystem::SetFilePointerEx(
                    handle,
                    (offset + INITIALIZATION_OFFSET) as i64,
                    null_mut(),
                    FileSystem::FILE_BEGIN
                )
            };

            // Random Read/Compare test
            if test == Test::RandomReads {
                let now = Instant::now();
                while now.elapsed().as_secs() < hold_time as u64 {
                    // Generate random multiplier
                    let random_multiplier = rand::thread_rng().gen_range(0..random_multiplier_range);
                    let random_offset = random_multiplier * buffer_size;

                    // Move file pointer to random locations to conduct Random Reads/Compare test
                    _pointer = unsafe {
                        FileSystem::SetFilePointerEx(
                            handle,
                            (offset + INITIALIZATION_OFFSET + random_offset) as i64,
                            null_mut(),
                            FileSystem::FILE_BEGIN
                        )
                    };

                    // Read from random location
                    let read = unsafe {
                        FileSystem::ReadFile(
                            handle,
                            read_buffer,
                            buffer_size as DWORD,
                            bytes_completed_ptr,
                            null_mut()
                        )
                    };

                    if compare_pattern {
                        // Retrieve data from read buffer for comparison
                        read_buffer_ptr_raw = std::ptr::slice_from_raw_parts_mut(read_buffer, buffer_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
                        unsafe {
                            let buf_ptr: *mut [u64] = read_buffer_ptr_raw as *mut [u64];
                            read_buf = &mut *buf_ptr;
                        }
    
                        // Compare read buffer to pattern
                        received = read_buf[0];
                        if received != original_pattern {
                            error!(   
                                "Data corruption at offset {}! Iteration {}, Thread {}. Actual({:#018x}) vs Expected({:#018x})", pos, iterations, id, received, original_pattern
                            );
                        }
                        
                    }
    
                    if read == false {
                        error!("Thread {} encountered Error Code {}", id, win32::last_error());
                        break;
                    }

                }
                // Sleep for requested delay time before next cycle starts
                let wait_time = std::time::Duration::from_millis((delay_time * 1000) as u64);
                thread::sleep(wait_time);
                iterations += 1;
                if time > 0 && now.elapsed().as_secs() > time {
                    break;
                }
            } else {
                // Full read/compare
                while pos <= last_pos {

                    let read = unsafe {
                        FileSystem::ReadFile(
                            handle,
                            read_buffer,
                            buffer_size as DWORD,
                            bytes_completed_ptr,
                            null_mut()
                        )
                    };

                    if compare_pattern {
                        // Retrieve data from read buffer for comparison
                        read_buffer_ptr_raw = std::ptr::slice_from_raw_parts_mut(read_buffer, buffer_size as usize / std::mem::size_of::<u64>()) as *mut [u64];
                        unsafe {
                            let buf_ptr: *mut [u64] = read_buffer_ptr_raw as *mut [u64];
                            read_buf = &mut *buf_ptr;
                        }

                        // Compare read buffer to pattern
                        received = read_buf[0];
                        if received != original_pattern {
                            error!(   
                                "Data corruption at offset {}! Iteration {}, Thread {}. Actual({:#018x}) vs Expected({:#018x})", pos, iterations, id, received, original_pattern
                            );
                        }
                        
                    }

                    pos += bytes_completed as u64;
                    if read == false {
                        error!("Thread {} encountered Error Code {}", id, win32::last_error());
                        break;
                    }
                    

                    if test == Test::MovingInversions {
                        // Move pointer back to conduct write
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
                                buffer_size as DWORD,
                                bytes_completed_ptr,
                                null_mut()
                            )
                        };

                        if write == false {
                            error!("Thread {} encountered Error Code {}", id, win32::last_error());
                            break;
                        }
                    }
                    if time > 0 {
                        if now.elapsed().as_secs() > time {
                            break;
                        }
                    }
                }
                iterations += 1;
                if time > 0 && now.elapsed().as_secs() > time {
                    break;
                }
            }
            
        }
        if test == Test::ReadCompare || test == Test::RandomReads {      // These tests test should not repeat the initial write
            break;
        }
        i += 1;
        if time > 0 {
            if now.elapsed().as_secs() > time {
                break;
            }
        }
    }
    let elapsed_time = now.elapsed();
    debug!("Thread {} took {} seconds to finish", id, elapsed_time.as_secs());
    unsafe {
        // Clean up resources and close handle
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
    let buffer_size = calculate_nearest_multiple(sector_size, iosize);
    return (size, buffer_size, sector_size);
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


// Shift number by specific amount of bits
fn bit_shift(data: u64, iterations: u64) -> u64 {
    let rotation = iterations % 16;        // Reset after each digit has been shifted once
    let bit_count = rotation * 4;
    data.rotate_right(bit_count.try_into().unwrap())
}

fn parse_hex(src: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(src, 16)
}


// Calculates sector size and adds it to JSON object
fn get_physicaldisk(device_obj: &mut JsonValue, physical_number: u8) {
    let result: Result<PhysicalDrive, std::string::String> = PhysicalDrive::open(physical_number);
    let parsed_result = result.expect("Drive number does not exist on this machine");
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sector_size = disk_geometry.size() / disk_geometry.sectors();
    device_obj["Sector Size"] = sector_size.into();
}

fn get_firmware_info(device_obj: &mut JsonValue, unique_id: &str) {
    let ps_script = format!("
    $FormatEnumerationLimit = -1
    Get-StorageFirmwareInformation -UniqueId {} | Select-Object FirmwareVersionInSlot | Format-List", unique_id);
    match powershell_script::run(&ps_script) {
        Ok(output) => {
            let mut output_string: String = output.stdout().unwrap();
            output_string = (*output_string.trim()).to_string();
            let parts = output_string.split(" : ");
            for part in parts {
                if part.starts_with('{') {
                    device_obj["Firmware Version"] = JsonValue::String(String::from(&part[1..part.len() - 1]));
                }
            }
        }
        Err(_err) => {
            device_obj["Firmware Version"] = JsonValue::String(String::from("not found"));
        }
    }
    
}

// Parse the output of the PowerShell script (Get-PhysicalDisk)
fn parse_script(stdout: &str, id_json: &mut JsonValue) { 
    let slice = &stdout[2..stdout.len()];
    let device_ids = slice.split(split_char);   
    for mut device in device_ids {
        device = device.trim();
        if device.is_empty() {
            continue;
        }
        let device_fields = device.split("; ");
        let mut device_obj = object!{};
        for field in device_fields {
            // Parse individual fields
            let field_split = field.split('=');
            let mut identifier = "";
            for item in field_split {
                match item {
                    "DeviceId" | "FriendlyName" | "SerialNumber" | "MediaType" | "UniqueId" => identifier = item,
                    _ => {
                        if identifier != "" {
                            device_obj[identifier] = item.into();
                            if identifier == "DeviceId" {
                                let id = item.chars().next().expect("Error trying to parse empty string");
                                let id_num: u32 = item.parse().unwrap();
                                if id.is_numeric() {
                                    get_physicaldisk(&mut device_obj, id_num as u8);
                                }
                            } else if identifier == "UniqueId" {
                                let unique_id: &str = item;
                                get_firmware_info(&mut device_obj, unique_id);
                            }
                            identifier = "";
                        }
                    },
                }
            }
        }
        let _result = id_json.push(device_obj);
    }
}


// For parsing PowerShell output
fn split_char(c: char) -> bool {
    return c == '@' || c == '{' || c == '}';
}


fn get_buffer_size(input: &str) -> u64 {
    match input {
        "512b" => {
            return 512;
        },
        "1k" => {
            return 1024;
        },
        "2k" => {
            return 2048;
        },
        "4k" => {
            return PAGE_SIZE;
        },
        "8k" => {
            return PAGE_SIZE * 2;
        },
        "16k" => {
            return PAGE_SIZE * 4;
        },
        "32k" => {
            return PAGE_SIZE * 8;
        },
        "64k" => {
            return PAGE_SIZE * 16;
        },
        "128k" => {
            return PAGE_SIZE * 32;
        },
        "256k" => {
            return PAGE_SIZE * 64;
        },
        "512k" => {
            return PAGE_SIZE * 128;
        },
        "1m" => {
            return MEGABYTE;
        },
        "2m" => {
            return MEGABYTE * 2;
        },
        "4m" => {
            return MEGABYTE * 4;
        },
        &_ => {
            error!("Unsupported buffer size chosen. Supported buffer sizes: 512b, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m");
            return 0;
        }

    }
}


fn select_test_type(id: u8) -> Test {
    match id {      // Change this
        0 => {
            info!("Test: Any Pattern Full Write No Comparison - i*[>W]");
            return Test::WriteOnly;
        },
        1 => {
            info!("Test: Any Pattern 64 Bit Moving Inversions with Data Comparison - i*[>W 64*[>r,c,w~]]");
            return Test::MovingInversions;
        },
        2 => {
            info!("Test: Any Pattern 64 Bit Write and Read/Compare - [>W i*[>r,c]]");
            return Test::ReadCompare;
        },
        3 => {
            info!("Test: Any Pattern 64 Bit Write and Random Read/Compare - [>W i*[>rr,c,h,d]");
            return Test::RandomReads;
        },
        4 => {
            info!("Test: Any Pattern 64 Bit Random Write/Read/Compare - T*[>ww,r,c]");
            return Test::RandomWriteCycle;
        }
        _ => {
            info!("Test ID does not exist, defaulting to write only mode...");
            return Test::WriteOnly;
        }
    }
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

    // Buffer must be big enough to cintain both a STORAGE_PROPERTY_QUERY and a STORAGE_PROTOCOL_SPECIFIC_DATA structure
    let storage_property_query_offset = field_offset::offset_of!(Ioctl::STORAGE_PROPERTY_QUERY => AdditionalParameters).get_byte_offset();
    let buffer_length: usize = storage_property_query_offset + size_of::<Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA>() + NVME_MAX_LOG_SIZE as usize;

    let mut returned_length: u32 = 0;
    let returned_length_ptr: *mut u32 = &mut returned_length as *mut u32;

    // Allocate sector-aligned buffer with Win32 VirtualAlloc
    let buf: LPVOID = unsafe {
        VirtualAlloc(
            null_mut(),
            buffer_length as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    let buffer_ptr_raw: *mut u8 = std::ptr::slice_from_raw_parts_mut(buf, buffer_length as usize / std::mem::size_of::<u8>()) as *mut u8;

    unsafe {
        let query_ptr: *mut Ioctl::STORAGE_PROPERTY_QUERY = std::mem::transmute::<*mut u8, *mut Ioctl::STORAGE_PROPERTY_QUERY>(buffer_ptr_raw);
        let query: &mut Ioctl::STORAGE_PROPERTY_QUERY = &mut *query_ptr;

        let protocol_data_ptr: *mut Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA = std::mem::transmute::<*mut u8, *mut Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA>(query.AdditionalParameters.as_mut_ptr());
        let protocol_data: &mut Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA = &mut *protocol_data_ptr;
        
        
        query.PropertyId = Ioctl::StorageAdapterProtocolSpecificProperty;
        query.QueryType = Ioctl::PropertyStandardQuery;

        protocol_data.ProtocolType = Ioctl::ProtocolTypeNvme;
        protocol_data.DataType = 1;     // Ioctl::NVMeDataTypeIdentify is not implemented correctly, so use simple 
        protocol_data.ProtocolDataRequestValue = 1;     // NVME_IDENTIFY_CNS_CONTROLLER
        protocol_data.ProtocolDataRequestSubValue = 0;
        protocol_data.ProtocolDataOffset = size_of::<Ioctl::STORAGE_PROTOCOL_SPECIFIC_DATA>() as u32;
        protocol_data.ProtocolDataLength = NVME_MAX_LOG_SIZE;

        let result: Foundation::BOOL = DeviceIoControl(h_device,
            Ioctl::IOCTL_STORAGE_QUERY_PROPERTY,
            buf,
            buffer_length as u32,
            buf,
            buffer_length as u32,
        returned_length_ptr,
            null_mut()
        );

        if !result.as_bool() || (returned_length == 0) {
            status = win32::last_error();
            error!("Get Identify Controller Data failed. Error Code {}", status);
            exit(1);
        }
    
        let write_buffer_ptr_raw: *mut [u8] = std::ptr::slice_from_raw_parts_mut(buf, buffer_length as usize / std::mem::size_of::<u8>()) as *mut [u8];
        let write_buf: &mut [u8];
        let buf_ptr: *mut [u8] = write_buffer_ptr_raw as *mut [u8];
        write_buf = &mut *buf_ptr;

        // Parse byte output
        parse_controller_buffer(write_buf, protocol_data.ProtocolDataOffset as usize + storage_property_query_offset as usize);
    }
    
}


// Parse the output of the Identify Controller NVMe information
#[allow(non_snake_case)]
fn parse_controller_buffer(buffer: &mut [u8], offset: usize) {
    for i in offset..offset + 84 {
        debug!("{}: {:#02X}", i, buffer[i as usize]);
    }

    // Print Vendor ID
    let VID = format!("{:#02X}{:02X}", buffer[offset + 1], buffer[offset]);
    println!("PCI Vendor ID (VID): {}", VID);

    // Print SS Vendor ID
    let SSVID = format!("{:#02X}{:02X}", buffer[offset + 3], buffer[offset + 2]);
    println!("PCI Subsystem Vendor ID (SSVID): {}", SSVID);

    // Print Serial Number
    let mut SN = format!("{:#02X}", buffer[offset + 4]);
    for i in offset + 5..offset + 23 {
        SN += &format!("{:02X}", buffer[offset + i]);
    }
    println!("Serial Number (SN): {}", SN);

    // Print Model Number
    let mut MN = format!("{:#02X}", buffer[offset + 24]);
    for i in offset + 25..offset + 63 {
        MN += &format!("{:02X}", buffer[offset + i]);
    }
    println!("Model Number (MN): {}", MN);

    // Print Firmware Revision
    let mut FR = format!("{:#02X}", buffer[offset + 64]);
    for i in offset + 65..offset + 71 {
        FR += &format!("{:02X}", buffer[offset + i]);
    }
    println!("Firmware Revision (FR): {}", FR);

    // Print Recommended Arbitration Burst
    println!("Recommended Arbitration Burst (RAB): {:#02X}", buffer[offset + 72]);

    // Print IEEE OUI Identifier
    let IEEE = format!("{:#02X}{:02X}{:02X}", buffer[offset + 75], buffer[offset + 74], buffer[offset + 75]);
    println!("IEEE OUI Identifier: {}", IEEE);

    // Print Maximum Data Transfer Size
    println!("Maximum Data Transfer Size (MDTS): {:#02X}", buffer[offset + 77]);

    // Print Controller ID
    let CNTLID = format!("{:#02X}{:02X}", buffer[offset + 79], buffer[offset + 78]);
    println!("Controller ID (CNTLID): {}", CNTLID);

     // Print Version
     let mut VER = format!("{:#02X}", buffer[offset + 80]);
     for i in offset + 81..offset + 83 {
         VER += &format!("{:02X}", buffer[offset + i]);
     }
     println!("Version (VER): {}", VER);

}
