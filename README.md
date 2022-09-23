# RDXtreme - Storage Device I/O Testing Tool
_A multithreaded I/O testing tool designed for physical storage devices_

## _About_
This CLI allows you to run multithreaded read/write operations and data comparison tests on storage devices. It is written entirely in Rust and PowerShell and supports custom data patterns, buffer sizes, thread counts, and more.

## Dependencies

* **This program is designed for Windows 10/11**

[Rust](https://www.rust-lang.org/tools/install)

[Cargo](https://www.rust-lang.org/tools/install)

[PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.2)


## _**Setup for Development**_

1. `git clone` or download this repository
2. `cargo install` to install libraries and crates
3. `cargo build --release` to compile and build .exe
    - `cargo build --target=aarch64-pc-windows-msvc` for ARM64


## _**Usage**_

**This tool must be run with Administrator privileges in PowerShell**

```
./rdxtreme.exe -w/-r -p [disk #] -t [THREADS] -P [PATTERN] -g/-m [LIMIT] -b [SIZE] -i [ITERATIONS] -T [TEST] [...]
```

### Flags

`-p/--physical-disk` : Physical disk ID to run I/O operations on

`-r/--read` : Read/compare mode

`-w/--write` : Write mode

`-T/--test [ID]` : Test to run (tests defined below)

`-t/--threads [THREADS]` : Number of threads to use

`-n/--no-compare` : Disable data comparisons

`-g/--limitgb [LIMIT]` : I/O limit (in GB)

`-m/--limitmb [LIMIT]` : I/O limit (in MB)

`-P/--pattern [NUM]` : Data pattern to use for writes/comparisons

`-b/--buffer [SIZE]` : Buffer/IO operation size (512b, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m)

`-x/--trigger` : Exit/pattern trigger for the I/O test (more information below)

`--time [LENGTH]` : Time limit (s) before program exits

`-h/--hold` : Time (s) to run each random read for (only for specific test cases)

`-d/--delay` : Time (s) before running random reads again (only for specific test cases)

`-i/--iterations [LOOPS]` : Number of times to conduct I/O test 

`--use-groups` : Optional flag that allows program to utilize multiple processor groups for increased performance

`--debug` : Print debug information in log output

`--info` : Print information about the machine's physical drives

`-C/--controller` : Print Identify Controller information

`-N/--namespace` : Print Identify Namespace information

`-F/--firmware` : Print Firmware information


## _**Tests**_

### **0. Write Only (Default)**
```Any Pattern Full Write No Comparison - i*[>W]```

- Write full data pattern '--iteration' times

### **1. Moving Inversions**
```Any Pattern 64 Bit Moving Inversions with Data Comparison - i*[>W 64*[>r,c,w~]]```

- Write full data pattern then read/compare/write bit-shifted pattern 64 times and repeat '--iteration' more times

### **2. Read Compare**
```Any Pattern 64 Bit Write and Read/Compare - [>W i*[>r,c]]```

- Read/compare drive to requested data pattern '--iteration' times

### **3. Random Read/Compare**
```Any Pattern 64 Bit Write and Random Read/Compare - [>W i*[>rr,c,h,d]```

- Write full data pattern then continuously read and compare at random addresses

### **4. Random Write/Read/Compare**
```Any Pattern 64 Bit Random Write/Read/Compare - T*[>ww,r,c]```

- Write, read, and compare full data pattern at random addresses

## _**Exit Triggers**_

### **0. Default**

- Exit on fatal errors only

### **1. Exit on Any Error**

- Stop all threads on a data mismatch or any other error

### **2. Triggering Data Pattern**

- Write `0xEFBEADDEADDEADDE` once to the LBA at the 4 KB offset upon a data mismatch, "marking" the drive


## _**Use Cases**_

Output from `./rdxtreme.exe --info`:

```
DeviceId FriendlyName         SerialNumber                             MediaType Partitions Sector Size
-------- ------------         ------------                             --------- ---------- -----------
0        Msft Virtual Disk    N/A                                      Unspecified        3         512
1        KXG60PNV2T04 TOSHIBA 0000_0000_0000_0001_8CE3_8E05_0088_2698. SSD                1         512

```

### **Initializing SSDs to Steady State:**
```
./rdxtreme.exe --physical-disk 1 --threads 64 --iterations 2 --buffer 4m --test 2 --use-groups --no-compare
```
- Write/read test runs 2 times with a large buffer size and multiple threads. Comparisons disabled for maximum performance


### **Stress-Test Drives:**
```
./rdxtreme.exe --physical-disk 1 --threads 128 --iterations 5 --pattern 0123456789abcdef --buffer 128k --test 1 --no-compare
```
- Moving inversions data comparison test runs 100 times with many threads and a medium-sized buffer without comparisons


### **Find Hardware Deficiencies:**
```
./rdxtreme.exe --physical-disk 1 --threads 32 --iterations 10 --pattern aaaaaaaaaaaaaaa9 --buffer 16k --test 2 --debug --use-groups
```
- Read/compare test with a small buffer size and log debug information 
