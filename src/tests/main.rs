use windows_drives::drive::{PhysicalDrive, DiskGeometry};
use windows_drives::win32;
use windows_drives::win32::last_error;
use sysinfo::{SystemExt};
use powershell_script;
use clap::Arg;
use std::time::Instant;
use std::{
    io::{Read, Seek},
    ptr::null_mut,
};
use winapi::{
    shared::minwindef::{LPCVOID, DWORD},
    um::{
        fileapi::{self as fs, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FILE_FLAG_OVERLAPPED},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, HANDLE},
    },
};

const MEGABYTE: u64 = 1048576;

fn main() {
    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    let args = clap::App::new("Disk Analyzer")
        .version("v0.1.0")
        .author("Made by Arjun")
        .about("CLI to conduct read/write IO operations on single-partition physical disks")
        .arg(Arg::new("write")
            .short('w')
            .long("write")
            .takes_value(true))
        .arg(Arg::new("read")
            .short('r')
            .long("read")
            .takes_value(true))
        .get_matches();

    // TODO: Fix redundancy here
    let partitions: u8;
    let disk_number: u8;
    if args.is_present("read") {
        disk_number = args.value_of("read").unwrap().parse().expect("Disk number must be a valid integer!");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            panic!("Cannot conduct IO operations on disk with multiple partitions, exiting...");
        }
        conduct_read_io(disk_number);
    } else if args.is_present("write") {
        disk_number = args.value_of("write").unwrap().parse().expect("Disk number must be a valid integer!");
        partitions = get_partitions(disk_number);
        if partitions > 1 {
            panic!("Cannot conduct IO operations on disk with multiple partitions, exiting...");
        }
        conduct_write_io(disk_number);
    } else {
        // let output = powershell_script::run(r#"
        //         Get-PhysicalDisk | Sort-Object -Property { [int]$_.DeviceId } | Select-Object DeviceId
        //         "#).unwrap();
        // let output_string = output.stdout().unwrap();
    }
}

// Use powershell script to find number partitions for a given physical disk
fn get_partitions(disk_number: u8) -> u8 {
    let ps_script = format!("[array]$Partitions = Get-Partition {}
                            Write-Output ($Partitions.count)", disk_number);
    let output = powershell_script::run(&ps_script).unwrap();
    let mut output_string: std::string::String = output.stdout().unwrap();
    output_string = (*output_string.trim()).to_string();
    let partition_number: u8 = output_string.parse().unwrap();
    return partition_number;
}


// Read through given physical disk in ~1 MB chunks
fn conduct_read_io(disk_number: u8) {
    let result: Result<PhysicalDrive, std::string::String> = PhysicalDrive::open(disk_number);
    let mut parsed_result: PhysicalDrive = result.expect("Error opening physical disk");
    let mut pos: u64 = 0;
    let size: u64 = parsed_result.size();
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sector_size = disk_geometry.size() / disk_geometry.sectors();
    println!("Disk {} size: {} bytes", disk_number, size);
    let readsize = calculate_readsize(sector_size);
    let mut buf = vec![0; readsize as usize];
    let now = Instant::now();
    let last_pos = size - readsize;
    while pos < last_pos {
        pos = PhysicalDrive::stream_position(&mut parsed_result).unwrap();

        // Read up to 1 mB
        let _bytes_read = PhysicalDrive::read(&mut parsed_result, &mut buf).unwrap_or(0);
    }
    let elapsed_time = now.elapsed();
    println!("Drive {} took {} seconds to read", disk_number, elapsed_time.as_secs());
}


// Write blank data pattern to physical drive in 2948-byte chunks
fn conduct_write_io(disk_number: u8) {
    let result: Result<PhysicalDrive, std::string::String> = PhysicalDrive::open(disk_number);
    let parsed_result: PhysicalDrive = result.expect("Error opening physical disk");
    let mut bytes_to_write: u64 = parsed_result.size();
    println!("Disk {} size: {} bytes", disk_number, bytes_to_write);
    let path = format_drive_num(disk_number);
    let handle = open_write_handle(&path).unwrap();
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sector_size = disk_geometry.size() / disk_geometry.sectors();
    let writesize = calculate_readsize(sector_size);
    let mut bytes_written: u32 = 0;
    let bytes_written_ptr: *mut u32 = &mut bytes_written;
    let buf = vec!['a'; 2048 as usize];
    let buf_ptr: LPCVOID = &buf as *const _ as LPCVOID;
    let now = Instant::now();
    loop {
        let write = unsafe {
            fs::WriteFile(
                handle,
                buf_ptr,
                2048 as DWORD,     // use OVERLAPPED to set byte offset, 
                bytes_written_ptr,
                null_mut()
            )
        };
        // println!("Bytes left: {}", bytes_to_write);
        bytes_to_write -= bytes_written as u64;
        if bytes_to_write == 0 {
            break;
        }
        if write < 1 {
            println!("Encountered Error Code {}", last_error());
            break;
        }
    }
    unsafe {
        CloseHandle(handle);
    }
    let elapsed_time = now.elapsed();
    println!("Drive {} took {} seconds to write to", disk_number, elapsed_time.as_secs());
}


// Calculate and return nearest multiple of given sector size to 1 MB
fn calculate_readsize(multiple: u64) -> u64 {
    let remainder = MEGABYTE % multiple;
    if remainder == 0 {
        return MEGABYTE.into();
    }
    return (MEGABYTE + multiple - remainder).into();
}


// Leverage Win32 to open a physical drive handle for writing
fn open_write_handle(path: &str) -> Result<HANDLE, String> {
    let path = win32::win32_string(&path);
    let handle = unsafe {
        fs::CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,     // win32 has File Buffering limitations affecting write size
            null_mut(),
        )
    };
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
fn format_drive_num(drive_num: u8) -> std::string::String {
    return format!("\\\\.\\PhysicalDrive{}", drive_num);
}
