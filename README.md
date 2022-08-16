# Storage Device I/O Testing Tool
_A multithreaded I/O testing tool designed for physical storage devices

## _About_
This CLI allows you to run multithreaded read/write operations on physical storage devices. Users can specify the number of threads, I/O limits, and specific data patterns to write for testing purposes.

## Dependencies

* **This program is designed for Windows 10/11**

[Rust](https://www.rust-lang.org/tools/install)

[Cargo](https://www.rust-lang.org/tools/install)

[PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.2)


## _Setup_

1. `git clone` or download this repository
2. `cargo install` to install libraries and crates
3. `cargo build --release` to compile and build .exe
4. `cargo run -- [FLAGS]` or run exe directly in `target/release/unbuffered_io.exe [FLAGS]`

## _Usage_
Run `physical_disks.exe -a` in PowerShell to see a list of your machine's physical disks along with partition information, device health, etc.

1. Reads
	```
	storageiotool.exe -r [disk #] -t [THREADS] -p [PATTERN] [-l] [LIMIT (in GB)]
	```
2. Writes
	```
	storagetiotool.exe -w [disk #] -t [THREADS] -p [PATTERN] -l [LIMIT]	
	```

### Optional Flags
`-t` : Number of threads to use

`-l` : I/O limit (in GB)

`-p` : Data pattern to use for writes/comparisons

## _Performance_
