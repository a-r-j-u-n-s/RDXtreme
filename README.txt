Usage:

Run "physical_disks.exe -a" in PowerShell to see a list of your machine's physical disks along with partition information, device health, etc.

1. Reads
	
	storageiotool.exe -r [DISK #] -t [THREADS] -p [PATTERN] -g/-m [LIMIT (in GB or MB)] -i [I/O SIZE]
	
2. Writes
	
	storagetiotool.exe -w [disk #] -t [THREADS] -p [PATTERN] -g/-m [LIMIT (in GB or MB)] -i [I/O SIZE]
	

Optional Flags

`-t` : Number of threads to use

`-g` : I/O limit (in GB)

`-m` : I/O limit (in MB)

`-p` : Data pattern to use for writes/comparisons

`-i` : I/O size (in MB)