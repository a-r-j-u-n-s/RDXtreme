# Storage Device I/O Testing Tool
_A multithreaded I/O testing tool designed for physical storage devices_

## _About_
This CLI allows you to run multithreaded read/write operations on physical storage devices. Users can specify the number of threads, I/O limits, and specific data patterns to write for testing purposes.

## Dependencies

* **This program is designed for Windows 10/11**

[Rust](https://www.rust-lang.org/tools/install)

[Cargo](https://www.rust-lang.org/tools/install)

[PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.2)


## _**Setup for Development**_

1. `git clone` or download this repository
2. `cargo install` to install libraries and crates
3. `cargo build --release` to compile and build .exe
4. `cargo run -- [FLAGS]` or run exe directly in `target/release/storageiotool.exe [FLAGS]`

## _**Usage**_

**This tool must be run with Administrator privileges in PowerShell**

```
./storagetiotool.exe -w/-r [disk #] -t [THREADS] -p [PATTERN] -g/-m [LIMIT] -b [SIZE] -i [ITERATIONS] [...]
```

### Flags

`-r/--read [ID]` : Read

`-w/--write [ID]` : Write

`-t/--threads [THREADS]` : Number of threads to use

`-g/--limitgb [LIMIT]` : I/O limit (in GB)

`-m/--limitmb [LIMIT]` : I/O limit (in MB)

`-p/--pattern [HEX]` : Data pattern to use for writes/comparisons

`-b/--buffer [SIZE]` : Buffer/IO operation size (512b, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m)

`--time [LENGTH]` : How long (seconds) to run the operation for

`-i/--iterations [LOOPS]` : Number of times to conduct I/O operations 

`--use-groups` : Optional flag that allows program to utilize multiple processor groups for increased performance

`--debug` : Print debug information in log output

`--info` : Print information about the machine's physical drives


## _**Example Use Case: Data Comparison**_

Output from `./storageiotool.exe --info`:

```
DeviceId FriendlyName         SerialNumber                             MediaType Partitions Sector Size
-------- ------------         ------------                             --------- ---------- -----------
0        KXG60PNV2T04 TOSHIBA 0000_0000_0000_0001_8CE3_8E05_0088_2698. SSD                4         512

```

### Options
`1*[>W 64*[>r,c,w~]]` is the supported data comparison pattern

```
./storagetiotool.exe -w 0 -t 64 -p 0123456789abcdef -g 10 -b 1m -i 4 --use-groups --debug
```

This set of commands will continuously write/read/compare/shift the pattern "0x0123456789abcdef" to the first 10 GB of the TOSHIBA storage device. During the process, any anomalies such as data corruptions or Win32 errors will be printed to the console. With these parameters, the given pattern will be duplicated into a 1 MB buffer which will be continously written, shifted, and read, and compared by 64 concurrent threads. Each write/read will be 1 MB, and the entire operation will repeat itself 4 times. Since this computers has many processor groups, `--use-groups` tells the program to spread its threads across multiple processor groups. `--debug` is enabled, so information about the threads' statuses will also be printed to the console.
