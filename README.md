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
./go-clam -d /Users/klarsen/Downloads/last_grpn/files
[*] Running freshclam
[*] Scanning directory: /Users/klarsen/Downloads/last_grpn/files
[*] Found 8 files
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34 (1).vbox-extpack
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34.vbox-extpack
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/.DS_Store
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Docker.dmg
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg
[*] /Users/klarsen/Downloads/last_grpn/files/.DS_Store: OK

[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip
[*] /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg: OK

[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64
[*] /Users/klarsen/Downloads/last_grpn/files/packer: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Docker.dmg: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34.vbox-extpack: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Oracle_VM_VirtualBox_Extension_Pack-6.1.34 (1).vbox-extpack: OK

[*] /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64: OK

[*] /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip: OK

[*] Finished scanning directory
```
