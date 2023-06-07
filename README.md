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
- go build -o ~/go/bin/go-clam

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
klarsen@Mac-Book-Pro2 ~ % go-clam -d ~/Downloads/last_grpn/files
[*] Scanning directory: /Users/klarsen/Downloads/last_grpn/files
[*] Found 6 files
Number of CPU cores: 12
Number of threads to use: 6
[*] Scanning file .DS_Store
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/.DS_Store: OK

[*] Scanning file Docker.dmg.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/Docker.dmg.zip: OK

[*] Scanning file VirtualBox-6.1.34-150636-OSX.dmg.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg.zip: OK

[*] Scanning file terragrunt_darwin_amd64
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64: OK

[*] Scanning file packer.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/packer.zip: OK

[*] Scanning file packer_1.8.2_darwin_amd64.zip
[+] File is ok
/Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip: OK

[*] Finished scanning directory
```
