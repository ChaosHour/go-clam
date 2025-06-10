# go-clam

A high-performance wrapper for ClamAV.

## Installation

### Prerequisites

1. Make sure you have ClamAV installed on your system:

   ```bash
   # On macOS with Homebrew
   brew install clamav

   # On Ubuntu/Debian
   sudo apt-get install clamav clamav-daemon
   ```

2. Build the go-clam binary:

   ```bash
   make build
   ```

## Performance Tips

For best performance, use the following options:

1. **Use clamd**: The ClamAV daemon is much faster than clamscan

   ```bash
   ./bin/go-clam -clamd
   ```

2. **Filter files by extension**: Only scan files that might contain viruses

   ```bash
   ./bin/go-clam -include exe -include dll -include js
   ```

3. **Skip large files**: Set a maximum file size to scan

   ```bash
   ./bin/go-clam -max-size 50  # Skip files larger than 50MB
   ```

4. **Skip hidden files**: Hidden files are rarely infected

   ```bash
   ./bin/go-clam -skip-hidden
   ```

5. **Adjust concurrency**: For very large storage systems, increase concurrency

   ```bash
   ./bin/go-clam -concurrency 16
   ```

## Performance Tuning

### Thread Management

By default, go-clam intelligently sets the number of threads to half your CPU cores (e.g., 6 threads for a 12-core machine). This default is balanced to:

- Provide good scanning performance
- Avoid overwhelming your system
- Leave CPU resources for other tasks
- Account for I/O bottlenecks in scanning

This is optimal for most systems, but you can adjust this with the `-concurrency` flag:

```bash
# For dedicated scanning servers, use more threads
./bin/go-clam -concurrency 10 -d /path/to/scan

# For background scanning on active workstations, use fewer threads
./bin/go-clam -concurrency 3 -d /path/to/scan
```

### When to adjust concurrency

- **Increase threads**: On servers dedicated to scanning with fast storage (SSDs)
- **Decrease threads**: When running on machines that need to stay responsive for other tasks
- **Use default (half cores)**: For most general scanning tasks

## File Selection and Counting

When comparing `ls` output to the files go-clam reports, you might notice a difference (e.g., `ls` shows 79 files but go-clam scans 65). This is because go-clam:

- Skips directories (only scans actual files)
- By default, skips files larger than 100MB (configurable with `-max-size`)
- Applies extension filters if you use `-include` or `-exclude`
- May skip files it can't access due to permissions

To see exactly which files are being skipped, use the verbose flag:

```bash
./bin/go-clam -v -d /path/to/scan
```

## Using Multiple Directories

You can scan multiple directories by specifying the `-d` flag multiple times:

```bash
./bin/go-clam -d /path/to/dir1 -d /path/to/dir2
```

## Understanding the Output

When running a scan, you'll see:

```bash
[*] Updating virus definitions
[*] Discovering files in directories: [your-directory-path]
[*] Found X files to scan
Number of CPU cores: Y
Number of threads to use: Z

Scanning files  XX% ==============================---------- (N/T) [Time:Remaining]
```

- The progress bar shows the current scan progress
- Files detected as infected will be shown in red
- Infected files are automatically moved to your ~/infected directory
- At the end of the scan, you'll see performance statistics (files per second)

## Recommended Scanning Strategy

For optimal performance and thorough scanning:

```bash
# Fast initial scan for common threats
./bin/go-clam -clamd -include exe -include dll -include js -include pdf -include doc -include docx -d /path/to/scan

# For a more thorough scan if needed
./bin/go-clam -clamd -max-size 100 -d /path/to/scan
```

## Common Usage Examples

```bash
# Scan with a larger maximum file size (500 MB)
./bin/go-clam -max-size 500 -d /path/to/scan

# go-clam scans subdirectories by default
# (recursive scanning is built-in, no additional flags needed)
```

## Using clamd for Faster Scanning

The `-clamd` option significantly improves scanning speed, but requires proper setup:

### Setting up clamd on macOS

1. Install ClamAV with Homebrew:

```bash
   brew install clamav
   ```

2.Configure clamd:

```bash
   # Edit the example configuration files
   cd /usr/local/etc/clamav/
   sudo cp freshclam.conf.sample freshclam.conf
   sudo cp clamd.conf.sample clamd.conf
   
   # Edit the configuration files to uncomment the Example line
   sudo sed -i '' 's/^Example/#Example/' freshclam.conf
   sudo sed -i '' 's/^Example/#Example/' clamd.conf
   ```

3.Start the service using Homebrew:

```bash
   # Start as a regular user (recommended for most cases)
   brew services start clamav
   
   # Only use sudo if you need it to start at system boot
   # Note: This changes ownership of some paths to root which can cause issues with brew upgrades
   # sudo brew services start clamav
   
   # Alternatively, run it in the foreground for testing
   # /usr/local/opt/clamav/sbin/clamd --foreground
   ```

4.Fix socket permissions:

```bash
   # Check the current socket configuration
   grep LocalSocket /usr/local/etc/clamav/clamd.conf
   # This shows: LocalSocket /usr/local/var/run/clamav/clamd.sock
   
   # Create the directory if it doesn't exist
   sudo mkdir -p /usr/local/var/run/clamav/
   
   # Fix permissions so your user can access it
   sudo chown -R $(whoami) /usr/local/var/run/clamav/
   
   # Restart the service
   brew services restart clamav
   
   # Verify the socket is created and accessible
   ls -l /usr/local/var/run/clamav/
   ```

5.Use the socket path with go-clam:

```bash
   # Correct way to specify the socket path (no need for $() syntax)
   ./bin/go-clam -clamd -socket=/usr/local/var/run/clamav/clamd.sock -d /path/to/scan
   
   # Alternative with quoted path if it contains special characters
   ./bin/go-clam -clamd -socket "/usr/local/var/run/clamav/clamd.sock" -d /path/to/scan
   
   # DO NOT use this syntax (this will cause "permission denied" errors)
   # ./bin/go-clam -clamd -socket=$(/usr/local/var/run/clamav/clamd.sock) -d /path/to/scan
```

### Setting up clamd on Linux

1. Install ClamAV and the daemon:

```bash
   sudo apt-get install clamav clamav-daemon
   ```

2.Start the service:

```bash
   sudo systemctl start clamav-daemon
   ```

3.Check the socket path:

```bash
   ls /var/run/clamav/
   ```

4.Use with go-clam:

```bash
   ./bin/go-clam -clamd -d /path/to/scan
   ```

## Running as User vs. Root

### Best Practice: Run as a Regular User

For most personal scanning needs, you should run go-clam as a regular user:

```bash
./bin/go-clam -d ~/Downloads
```

**Benefits of running as a regular user:**

- More secure - follows the principle of least privilege
- No risk of accidentally modifying system files
- Safe for automated/scheduled scans

**When user-level scanning is sufficient:**

- Scanning your home directory or personal files
- Checking downloaded files before using them
- Regular maintenance scans of your user data

### When Root Access is Necessary

Root access should only be used when you need to scan system directories:

```bash
sudo ./bin/go-clam -d /var/www -d /etc
```

**Important safety precautions when running as root:**

- Be extremely careful with the `-max-size` and exclude settings
- Consider using `--move` with caution or disable it when scanning system files
- Always review the results carefully before taking action

**Note:** When running with sudo, the infected files will be moved to the root user's ~/infected directory, not your user's home directory.

## Troubleshooting

### ClamAV Socket Connection Issues

If you see the error "ClamAV socket not found" even when the socket file exists:

```bash
# Verify the socket exists and has correct permissions
ls -lrt /usr/local/var/run/clamav/clamd.sock
# Should show something like: srw-rw-rw- 1 username admin 0 Jun 9 11:00 /usr/local/var/run/clamav/clamd.sock

# Check if clamd is actually running
ps aux | grep clamd

# Restart clamd and verify it's running
brew services restart clamav
brew services list | grep clamav

# Test the socket directly with nc
echo PING | nc -U /usr/local/var/run/clamav/clamd.sock
# Should respond with "PONG"

# Try using clamdscan directly to test if it can connect
clamdscan --version

# If all else fails, try running clamd manually to see any error messages
/usr/local/opt/clamav/sbin/clamd --foreground
```

If the socket exists but go-clam still can't connect, it might be a SELinux or extended attributes issue. Try:

```bash
# Remove extended attributes from the socket directory
sudo xattr -r -d com.apple.quarantine /usr/local/var/run/clamav/

# Restart clamd one more time
brew services restart clamav
```

### Advanced Socket Troubleshooting

If all the standard checks pass (socket exists, clamd is running, `nc` can connect, clamdscan works) but go-clam still can't connect:

```bash
# Make sure the socket permissions are correct
sudo chmod 666 /usr/local/var/run/clamav/clamd.sock

# Try with the absolute path to the socket
./bin/go-clam -clamd -socket=$(realpath /usr/local/var/run/clamav/clamd.sock) -d /path/to/scan

# Check if SELinux or macOS security features are blocking socket access
# On macOS, try:
sudo csrutil status
sudo spctl --status

# Try building go-clam with debug flags and running it with increased verbosity
go build -o bin/go-clam-debug cmd/clam/main.go
./bin/go-clam-debug -clamd -socket=/usr/local/var/run/clamav/clamd.sock -v -d /path/to/scan
```

If you're still encountering socket connection issues, you can fall back to using regular clamscan mode which doesn't require the socket:

```bash
# Fall back to regular clamscan mode
./bin/go-clam -d /path/to/scan
```

### Troubleshooting "exit status 2" Errors

If you're seeing multiple "Error scanning: exit status 2" messages when using clamd mode:

```bash
# First, try running clamdscan directly to see if it works
clamdscan --stream --fdpass ~/Downloads/test/somefile.txt

# Check the clamdscan version matches the clamd version
clamdscan --version
clamd --version

# Verify clamd configuration by running manually with debug
sudo /usr/local/opt/clamav/sbin/clamd --config-file=/usr/local/etc/clamav/clamd.conf --debug

# Try using clamdscan without the stream option in go-clam
# Create a test file that simply uses direct scanning:
cat > test_clamd.go << 'EOF'
package main

import (
    "fmt"
    "os"
    "os/exec"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Please provide a file to scan")
        return
    }
    
    cmd := exec.Command("clamdscan", os.Args[1])
    output, err := cmd.CombinedOutput()
    fmt.Println(string(output))
    if err != nil {
        fmt.Println("Error:", err)
    }
}
EOF
go run test_clamd.go ~/Downloads/test/somefile.txt

# If all else fails, fall back to regular clamscan mode which is more reliable
./bin/go-clam -d ~/Downloads/test
```

You might need to adjust the clamdscan command options in the go-clam source code if there's a compatibility issue with your version of ClamAV.

### Fixing clamd Integration Issues

If clamdscan works fine when run directly:

```bash
clamdscan --stream --fdpass ~/Downloads/test/1000003788.jpg
# Shows: OK and proper scan summary
```

But go-clam shows "exit status 2" errors, there may be an issue with command-line options.

Here's a possible source code fix (`~/projects/go-clam/cmd/clam/main.go`):

```go
// Modified scanWithClamd function for better compatibility
func scanWithClamd(ctx context.Context, file string) ScanResult {
    // Remove the --stream and --fdpass options that might be causing issues
    cmd := exec.CommandContext(ctx, "clamdscan", "--no-summary", file)
    output, err := cmd.CombinedOutput()
    
    // Rest of function remains the same
    // ...
}
```

You can rebuild go-clam after making this change to see if it fixes the issue:

```bash
make build
./bin/go-clam -clamd -d ~/Downloads/test
```

Another workaround is to try the non-clamd mode which is more robust:

```bash
./bin/go-clam -d ~/Downloads/test
```

## All Options

```bash
Usage of go-clam:
  -d value
        Directory to scan (can be specified multiple times)
  -clamscan string
        Path to clamscan binary (default "clamscan")
  -clamd
        Use clamd socket instead of clamscan (faster)
  -socket string
        Path to clamd socket (default "/var/run/clamav/clamd.sock")
  -concurrency int
        Number of concurrent scans (0 = auto)
  -exclude value
        File extensions to exclude (can be specified multiple times)
  -freshclam string
        Path to freshclam binary (default "freshclam")
  -include value
        Only scan these file extensions (can be specified multiple times)
  -max-size int
        Maximum file size to scan in MB (0 for unlimited) (default 100)
  -skip-hidden
        Skip hidden files and directories
  -v    Enable verbose output
```

## Understanding Max File Size Settings

```bash
# Default behavior: Skip files larger than 100MB
./bin/go-clam -d /path/to/scan

# Scan larger files (10GB max)
./bin/go-clam -max-size 10000 -d /path/to/scan

# Scan all files regardless of size
./bin/go-clam -max-size 0 -d /path/to/scan
```

Notice how changing max-size can affect the number of files scanned:

- With default settings: ~65 files found
- With -max-size 10000: ~80 files found

This happens because the default setting skips files over 100MB, while the larger setting includes more files.

Choose a max-size value based on:

- System resources available (larger files need more memory)
- Scan speed requirements (larger files take longer to scan)
- The types of files you're scanning (video/image archives are often large)
