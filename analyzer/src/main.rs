use windows_drives::drive::{DiskGeometry, PhysicalDrive, PartitionInfo, HarddiskVolume};
use sysinfo::{SystemExt};
use clap::Arg;
use powershell_script;
use json::{object, JsonValue};
use std::fs::{File, remove_file};
use std::io::prelude::*;

fn main() {
    let args = clap::App::new("Disk Analyzer")
        .version("v0.1.0")
        .author("Made by Arjun")
        .about("CLI to analyze the Physical Drives/Hard Disk Volumes on the local machine")
        .arg(Arg::new("hard")
            .short('h')
            .long("hard")
            .takes_value(true))
        .arg(Arg::new("all")
            .short('a')
            .long("all")
            .takes_value(false))
        .get_matches();
        

    // Refresh system information so drives are up to date
    let mut sysinfo = sysinfo::System::new_all();
    sysinfo.refresh_all();

    // Run powershell script and parse output
    if args.is_present("all") {
        let get_physicaldisks_script = include_str!("get_physicaldisks.ps1");
        match powershell_script::run(get_physicaldisks_script) {
            Ok(output) => {
                let stdout = String::from(output.stdout().unwrap());
                let mut id_json = json::JsonValue::new_array();
		        parse_script(&stdout, &mut id_json);
                let serialized = json::stringify(id_json);
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
                    $Table = $DiskInfo | Format-Table 'DeviceId', 'FriendlyName', 'SerialNumber', 'MediaType', 'Partitions', 'Sector Size'
                    Write-Output $Table
                "#).unwrap();
                println!("{}", output.stdout().unwrap());
                let _result = remove_file("./disk_info.json").expect("Encountered error removing temporary JSON file");
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        } 
    } else {
        if args.is_present("hard") {
            let hard_number: u8 = args.value_of("hard").unwrap().parse().expect("Hard disk must be a number!");
            get_harddisk(hard_number);
        }
    }

}

fn get_harddisk(hard_number: u8) {
    println!("Hard Disk Volume Information:\n");
    let result: Result<HarddiskVolume, std::string::String> = HarddiskVolume::open(hard_number);

    let parsed_result = result.expect("Disk number does not exist on this machine");
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    println!("Size of hard disk volume: {} bytes\n", parsed_result.size());
    println!("Disk Geometry:\n");
    // Print Disk Geometry Information
    println!("Disk size: {}", disk_geometry.size());    
    println!("Number of sectors: {}", disk_geometry.sectors());
    let sector_size = disk_geometry.size() / disk_geometry.sectors();
    println!("Sector size: {} bytes\n", sector_size);
    
    // Get Partition Information
    let partition_info: PartitionInfo = parsed_result.partition_info;
    println!("Partition Information:\n");
    println!("Starting offset: {}", partition_info.starting_offset);
    println!("Partition length: {}", partition_info.partition_length);
    println!("Partition number: {}", partition_info.partition_number);
}

// Calculates sector size and adds it to JSON object
fn get_physicaldisk(device_obj: &mut JsonValue, physical_number: u8) {
    let result: Result<PhysicalDrive, std::string::String> = PhysicalDrive::open(physical_number);
    let parsed_result = result.expect("Drive number does not exist on this machine");
    let disk_geometry: DiskGeometry = parsed_result.geometry;
    let sector_size = disk_geometry.size() / disk_geometry.sectors();
    device_obj["Sector Size"] = sector_size.into();
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
                    "DeviceId" | "FriendlyName" | "SerialNumber" | "MediaType" => identifier = item,
                    _ => {
                        if identifier != "" {
                            device_obj[identifier] = item.into();
                            if identifier == "DeviceId" {
                                let id = item.chars().next().expect("Error trying to parse empty string");
                                let id_num: u32 = item.parse().unwrap();
                                if id.is_numeric() {
                                    get_physicaldisk(&mut device_obj, id_num as u8);
                                }
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

fn split_char(c: char) -> bool {
    return c == '@' || c == '{' || c == '}';
}