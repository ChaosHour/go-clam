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
klarsen@Mac-Book-Pro2 go-clam % go run main.go -d ~/Downloads/last_grpn/files
[*] Running freshclam
[*] Scanning directory: /Users/klarsen/Downloads/last_grpn/files
[*] Found 6 files
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg.zip
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer.zip
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/Docker.dmg.zip
[*] Scanning file: /Users/klarsen/Downloads/last_grpn/files/.DS_Store
[*] /Users/klarsen/Downloads/last_grpn/files/VirtualBox-6.1.34-150636-OSX.dmg.zip: OK

[*] /Users/klarsen/Downloads/last_grpn/files/.DS_Store: OK

[*] /Users/klarsen/Downloads/last_grpn/files/Docker.dmg.zip: OK

[*] /Users/klarsen/Downloads/last_grpn/files/terragrunt_darwin_amd64: OK

[*] /Users/klarsen/Downloads/last_grpn/files/packer_1.8.2_darwin_amd64.zip: OK

[*] /Users/klarsen/Downloads/last_grpn/files/packer.zip: OK

[*] Finished scanning directory
```
