# go-clam
A go wrapper around ClamAV


## The why?
- Seeing how to do it with Go
- Would it be faster?

> Results:
Still testing and modifying the code.



## Install
- go install github.com/ChaosHour/go-clam@latest

## Usage

```go
./go-clam -h
Usage of ./go-clam:
  -clamscan string
    	Path to clamscan binary (default "/usr/local/bin/clamscan")
  -d string
    	Directory to scan
  -freshclam string
    	Path to freshclam binary (default "/usr/local/bin/freshclam")
```

## Example Usage
```Go
klarsen@Mac-Book-Pro2 go-clam % go run main.go -d /Users/klarsen/Downloads/last_grpn/files
[*] Running freshclam
Current working dir is /usr/local/var/lib/clamav/
Loaded freshclam.dat:
  version:    1
  uuid:       343634e5-38b0-4adf-b642-e9f18792b697
ClamAV update process started at Wed May 17 15:48:11 2023
Current working dir is /usr/local/var/lib/clamav/
Querying current.cvd.clamav.net
TTL: 305
fc_dns_query_update_info: Software version from DNS: 0.103.8
Current working dir is /usr/local/var/lib/clamav/
check_for_new_database_version: Local copy of daily found: daily.cld.
query_remote_database_version: daily.cvd version from DNS: 26910
daily.cld database is up-to-date (version: 26910, sigs: 2034858, f-level: 90, builder: raynman)
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
[*] Found 8 files
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34.vbox-extpack
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34 (1).vbox-extpack
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/.DS_Store
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Docker.dmg
[*] /Users/klarsen/Downloads/last_grpn/files/.DS_Store: OK

[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip
[*] /Users/klarsen/Downloads/last_grpn/files/packer: OK

[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64
[*] /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Docker.dmg: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34 (1).vbox-extpack: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34.vbox-extpack: OK

[*] /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64: OK

[*] /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip: OK

[*] Finished scanning directory
```
