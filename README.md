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
Run `physical_disks.exe -a` in PowerShell to see a list of your machine's physical disks along with partition information, device health, etc.


```
storagetiotool.exe -w/-r [disk #] -t [THREADS] -p [PATTERN] -g/-m [LIMIT] -b [SIZE]
```

### Flags

`-r` : Read

`-w` : Write

`-t` : Number of threads to use

`-g` : I/O limit (in GB)

`-m` : I/O limit (in MB)

`-p` : Data pattern to use for writes/comparisons

`-b` : Buffer size (in MB)

## _**Example Use Cases**_

Output from `./physical_disks.exe -a`:

```
DeviceId FriendlyName         SerialNumber                             MediaType Partitions Sector Size
-------- ------------         ------------                             --------- ---------- -----------
0        KXG60PNV2T04 TOSHIBA 0000_0000_0000_0001_8CE3_8E05_0088_2698. SSD                4         512

```

### Data Comparison
`1*[>W 64*[>r,c,w~]]` is the supported data comparison pattern

```
./storagetiotool.exe -w 0 -t 64 -p 0123456789abcdef -g 10 -b 1
```

This set of commands will continuously write/read/compare/shift the pattern "0x0123456789abcdef" to the TOSHIBA storage device

