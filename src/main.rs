use windows_drives::{drive::{PhysicalDrive, DiskGeometry}, win32};
use windows::{core::PCWSTR, Win32::{Storage::FileSystem, Foundation, System::{Ioctl, IO::DeviceIoControl}}};
use sysinfo::SystemExt;
use powershell_script;
use clap::Arg;
use std::{time::Instant, mem::{size_of, drop}, ptr::{null_mut, null}, process::exit, thread, string::String, sync::mpsc::{channel, Sender, Receiver}};
use winapi::{shared::minwindef::{DWORD, LPVOID}, um::{fileapi::OPEN_EXISTING, winbase::FILE_FLAG_NO_BUFFERING, winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, memoryapi::VirtualAlloc}};
use affinity::*;

const MEGABYTE: u64 = 1048576;
const PAGE_SIZE: u64 = 4096;
const NVME_MAX_LOG_SIZE: u64 = 0x1000;

fn main() {
    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    let args = clap::App::new("Yet Another NVMe Tool")
        .version("v1.1.0")
        .author("Arjun Srivastava, Microsoft CHIE - ASE")
        .about("CLI to analyze and conduct multithreaded read/write IO operations on single-partition physical disks")
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
        .arg(Arg::new("controller")
            .short('c')
            .long("controller")
            .takes_value(true)
            .help("Display controller information for NVMe device"))
        .arg(Arg::new("namespace")
            .short('n')
            .long("namespace")
            .takes_value(true)
            .help("Display nanespace information for NVMe device"))
        .get_matches();

    let partitions: u8;
    let disk_number: u8;
    let mut threads: u64 = 1;
    let io_type: char;      // Identifier for opening handle and conducting IO
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
        // Get Identify Controller, Namespace, FirmwareInfo
        if args.is_present("controller") {
            disk_number = args.value_of("controller").unwrap().parse().expect("Disk number must be a valid integer!");
            let path = format_drive_num(disk_number);
            let handle: Foundation::HANDLE = open_handle(&path, 'r').unwrap();
            id_controller(handle);
            return;
        }

        println!("Please specify an IO operation (see --help for more information)");
        exit(0);
    }
    // Threading logic to handle reads/writes
    let num_threads = threads;
    let (sender, receiver): (Sender<String>, Receiver<String>) = channel();
    let (size, io_size, sector_size) = calculate_disk_info(disk_number);
    println!("Disk {} size: {} bytes", disk_number, size);
    let cores_in_group = get_core_num();
    println!("Cores: {}", cores_in_group);
    while threads != 0 {
        let sen_clone = sender.clone();
        if io_type == 'r' {
            thread::spawn(move || thread_read(sen_clone, disk_number, num_threads, threads.clone(), size, io_size, sector_size));
        } else if io_type == 'w' {
            thread::spawn(move || thread_write(sen_clone, disk_number, num_threads, threads.clone(), size, io_size, sector_size));
        }
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
            5 => "could not open handle because access was denied - do you have administrator privileges?".to_string(),
            _ => format!("got invalid handle: error code {:#08x}", err)
        })
    } else {
        Ok(handle)
    }
}


// Conduct multithreaded write operation
fn thread_write(senderr: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, size: u64, writesize: u64, sector_size: u64) {
    // println!("Starting thread {}", id);    // For debugging purposes
    let full_write_size = size / num_threads;
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'w').unwrap();

    // Set up FilePointer to start write at offset based on thread number
    let mut offset = (id - 1) * full_write_size;
    
    // Reset offset if not an even multiple of sector size
    offset = calculate_io_size(PAGE_SIZE, offset);

    let _pointer = unsafe {
        FileSystem::SetFilePointerEx(
            handle,
            (MEGABYTE + offset) as i64,     // Increase offset by 1 MB to avoid overwriting index table and other initialization data
            null_mut(),
            FileSystem::FILE_BEGIN
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

    let mut bytes_written: u32 = 0;
    let bytes_written_ptr: *mut u32 = &mut bytes_written;
    let mut pos: u64 = offset;
    let last_pos = full_write_size * id - writesize;

    let now = Instant::now();
    while pos <= last_pos {
        let write = unsafe {
            FileSystem::WriteFile(
                handle,
                buffer,
                writesize as DWORD,
                bytes_written_ptr,
                null_mut()
            )
        };
        pos += bytes_written as u64;
        if write == false {
            println!("Thread {} encountered Error Code {}", id, win32::last_error());
            break;
        }
    }
    let elapsed_time = now.elapsed();
    println!("Thread {} took {} seconds to finish", id, elapsed_time.as_secs());
    unsafe {
        Foundation::CloseHandle(handle);
    }
    senderr.send(format!("finished|{}", id)).unwrap();
}


// Conduct multithreaded read operation
fn thread_read(senderr: std::sync::mpsc::Sender<String>, disk_number: u8, num_threads: u64, id: u64, size: u64, readsize: u64, sector_size: u64) {
    // println!("Starting thread {}", id);    // For debugging purposes
    let full_read_size = size / num_threads;
    let path = format_drive_num(disk_number);
    let handle = open_handle(&path, 'r').unwrap();

    // Set up FilePointer to start read at offset based on thread number
    let mut offset = (id - 1) * full_read_size;

    // Reset offset if not an even multiple of sector size
    offset = calculate_io_size(PAGE_SIZE, offset);

    let _pointer = unsafe {
        FileSystem::SetFilePointerEx(
            handle,
            offset as i64,
            null_mut(),
            FileSystem::FILE_BEGIN
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
            FileSystem::ReadFile(
                handle,
                buffer,
                readsize as DWORD,
                bytes_read_ptr,
                null_mut()
            )
        };
        pos += bytes_read as u64;
        if read == false { 
            println!("Thread {} encountered Error Code {}", id, win32::last_error());
            break;
        }
    }
    let elapsed_time = now.elapsed();
    println!("Thread {} took {} seconds to finish", id, elapsed_time.as_secs());
    unsafe {
        Foundation::CloseHandle(handle);
    }
    senderr.send(format!("finished|{}", id)).unwrap();
}


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


// Calculate and return nearest number to "base" that is a multiple of "multiple"
fn calculate_io_size(multiple: u64, base: u64) -> u64 {
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

