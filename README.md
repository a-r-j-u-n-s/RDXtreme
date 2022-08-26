# Storage Device I/O Testing Tool
_A multithreaded I/O testing tool designed for physical storage devices_

## _About_
This CLI allows you to run multithreaded read/write operations on physical storage devices. Users can specify the number of threads, I/O limits, and specific data patterns to write for testing purposes.

## Dependencies

* **This program is designed for Windows 10/11**

[Rust](https://www.rust-lang.org/tools/install)

[Cargo](https://www.rust-lang.org/tools/install)

[PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.2)


## _**Setup**_

1. `git clone` or download this repository
2. `cargo install` to install libraries and crates
3. `cargo build --release` to compile and build .exe
4. `cargo run -- [FLAGS]` or run exe directly in `target/release/unbuffered_io.exe [FLAGS]`

## _**Usage**_

**This tool must be run with Administrator privileges in PowerShell**

```
./storagetiotool.exe -w/-r [disk #] -t [THREADS] -p [PATTERN] -g/-m [LIMIT] -b [SIZE]
```

### Flags

`-r` : Read

`-w` : Write

`-t` : Number of threads to use

`-g` : I/O limit (in GB)

`-m` : I/O limit (in MB)

`-p` : Data pattern to use for writes/comparisons

`-b` : Buffer/IO operation size (in multiples of 4 KB)

`--use-groups` : Optional flag that allows program to utilize multiple processor groups for increased performance

`--log` : Enables logging

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
./storagetiotool.exe -w 0 -t 64 -p 0123456789abcdef -g 10 -b 4 --use-groups --log
```

This set of commands will continuously write/read/compare/shift the pa  ttern "0x0123456789abcdef" to the first 10 GB of the TOSHIBA storage device. During the process, any anomalies such as data mismatches or Win32 errors will be printed to the console. With these parameters, the given pattern will be duplicated into a 16 KB buffer which will be continously written, shifted, and read, and compared by 64 concurrent threads. Each write/read will be 16 KB. Since this computers has many processor groups, `--use-groups` will slightly increase performance by pinning threads to processor cores across the groups. Logging is enabled

### Output

