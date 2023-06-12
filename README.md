# go-clam
A go wrapper around ClamAV


## The why?
- Seeing how to do it with Go
- Would it be faster?

> Results:
Still testing and modifying the code.


## Dependencies
- ClamAV `brew install clamav`


## Install
- go install github.com/ChaosHour/go-clam@latest

## Build
- go build -o ~/go/bin/go-clam

## Usage

```go
go-clam -h
Usage of go-clam:
  -clamscan string
    	Path to clamscan binary (default "clamscan")
  -d string
    	Directory to scan
  -freshclam string
    	Path to freshclam binary (default "freshclam")
```

## Example Usage
```Go
go-clam -d ~/Downloads/last_grpn/files
[*] Updating virus definitions
Current working dir is /usr/local/var/lib/clamav/
Loaded freshclam.dat:
  version:    1
  uuid:       343634e5-38b0-4adf-b642-e9f18792b697
ClamAV update process started at Sun Jun 11 22:56:20 2023
Current working dir is /usr/local/var/lib/clamav/
Querying current.cvd.clamav.net
TTL: 222
fc_dns_query_update_info: Software version from DNS: 0.103.8
Current working dir is /usr/local/var/lib/clamav/
check_for_new_database_version: Local copy of daily found: daily.cld.
query_remote_database_version: daily.cvd version from DNS: 26936
daily.cld database is up-to-date (version: 26936, sigs: 2036882, f-level: 90, builder: raynman)
fc_update_database: daily.cld already up-to-date.
Current working dir is /usr/local/var/lib/clamav/
check_for_new_database_version: Local copy of main found: main.cvd.
query_remote_database_version: main.cvd version from DNS: 62
main.cvd database is up-to-date (version: 62, sigs: 6647427, f-level: 90, builder: sigmgr)
fc_update_database: main.cvd already up-to-date.
Current working dir is /usr/local/var/lib/clamav/
check_for_new_database_version: Local copy of bytecode found: bytecode.cvd.
query_remote_database_version: bytecode.cvd version from DNS: 334
bytecode.cvd database is up-to-date (version: 334, sigs: 91, f-level: 90, builder: anvilleg)
fc_update_database: bytecode.cvd already up-to-date.

[*] Scanning directory: /Users/klarsen/Downloads/last_grpn/files
[*] Found 6 files
Number of CPU cores: 12
Number of threads to use: 6

   0% |                                                                                                                                                                                                          | (0/6, 0 it/hr) [0s:0s]
[+] Virus scan completed successfully


  16% |███████████████████████████████                                                                                                                                                                       | (1/6, 2 it/min) [25s:2m5s]

[*] Scanning file VirtualBox-6.1.34-150636-OSX.dmg.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg.zip: OK

[+] Virus scan completed successfully




[*] Scanning file Docker.dmg.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/Docker.dmg.zip: OK

[+] Virus scan completed successfully




[*] Scanning file .DS_Store
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/.DS_Store: OK

[+] Virus scan completed successfully


  66% |███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████                                                                    | (4/6, 28 it/min) [28s:4s]

[*] Scanning file terragrunt_darwin_amd64
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64: OK

[+] Virus scan completed successfully


  83% |███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████                                  | (5/6, 19 it/min) [1m20s:3s]

[*] Scanning file packer.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/packer.zip: OK

[+] Virus scan completed successfully


 100% |██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| (6/6, 4 it/min)


[*] Scanning file packer_1.8.2_darwin_amd64.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip: OK

[*] Finished scanning batch 1 of 1 batches
[*] Finished scanning directory
```
