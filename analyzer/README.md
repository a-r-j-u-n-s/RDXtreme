# Disk Analyzer

This program prints information about Physical Drives and/or Hard Disk Volumes on a local machine


### Flags:
```
-p <physical> [Int]    Select which Physical Drive to analyze
-h <hard> [Int]         Select which Hard Disk Volume to analyze
```


### Build:
Requirements:
 - Rust 
 - Cargo

Run the following commands
```
cargo build
cargo run -- [OPTIONS]
```

Depending on your operating system, it will make a .exe or a linux executable (ELF) file