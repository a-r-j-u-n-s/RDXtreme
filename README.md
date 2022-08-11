# Storage Device I/O Testing Tool
_A multithreaded I/O testing tool designed for physical storage devices on Windows_

## _About_
This CLI allows you to run multithreaded read/write operations on physical storage devices

## Dependencies

* **This program is designed for Windows 10/11**

[Rust](https://www.rust-lang.org/tools/install)

[Cargo](https://pypi.org/project/psutil/) (installed automatically)

[PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.2)


## _Setup_

1. `git clone` or download this repository
2. `cargo install` to install libraries and crates
3. `cargo build --release` to compile and build .exe
4. `cargo run -- [FLAGS]` or run exe directly in `target/release/unbuffered_io.exe [FLAGS]`

## Usage
Run `physical_disks.exe -a` in PowerShell to see a list of your machine's physical disks along with partition information, device health, etc.

1. Reads
	```
	unbuffered_io.exe -r [disk #] -t [THREADS]
	```
2. Writes
	```
	unbuffered_io.exe -w [disk #] -t [THREADS]
	```

