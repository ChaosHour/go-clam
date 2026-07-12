// A wrapper for ClamAV

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ChaosHour/go-clam/internal/clamd"
	"github.com/ChaosHour/go-clam/internal/display"
	"github.com/fatih/color"
)

// define the flags
var (
	dirs          multiStringFlag // Replace single dir with multiple dirs
	clamscanPath  = flag.String("clamscan", "clamscan", "Path to clamscan binary")
	freshclamPath = flag.String("freshclam", "freshclam", "Path to freshclam binary")
	verbose       = flag.Bool("v", false, "Enable verbose output")
	useClamd      = flag.Bool("clamd", false, "Use clamd socket instead of clamscan (faster)")
	clamdSocket   = flag.String("socket", "/var/run/clamav/clamd.sock", "Path to clamd socket")
	excludeExt    multiStringFlag // Add exclude extensions flag
	includeExt    multiStringFlag // Add include extensions flag
	maxFileSize   = flag.Int64("max-size", 100, "Maximum file size to scan in MB (0 for unlimited)")
	skipHidden    = flag.Bool("skip-hidden", false, "Skip hidden files and directories")
	concurrency   = flag.Int("concurrency", 0, "Number of concurrent scans (0 = auto)")
	fastMode      = flag.Bool("fast", false, "Enable fast mode (skip freshclam update, minimal output)")
	forceUpdate   = flag.Bool("update", false, "Force a virus definition update even if definitions are fresh")
)

// Define a custom flag type to handle multiple string values
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// Register the custom flags
func init() {
	flag.Var(&dirs, "d", "Directory to scan (can be specified multiple times)")
	flag.Var(&excludeExt, "exclude", "File extensions to exclude (can be specified multiple times)")
	flag.Var(&includeExt, "include", "Only scan these file extensions (can be specified multiple times; files without an extension are then skipped)")
}

// define the colors
var (
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
)

// Add logging configuration
var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

// ScanResult represents the outcome of scanning a file
type ScanResult struct {
	File    string
	IsClean bool
	Message string
	Error   error
}

// define freshclam function and print the output to the console
func freshclamCommand(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, *freshclamPath, "-v")
}

// clamavDBDirs are the common virus-definition locations across platforms
// and package managers.
var clamavDBDirs = []string{
	"/var/lib/clamav",
	"/usr/local/share/clamav",
	"/usr/local/var/lib/clamav",
	"/opt/homebrew/var/lib/clamav",
	"/opt/local/share/clamav",
}

// definitionsAge returns the age of the newest virus-definition file found
// in dirs, or an error when none exist.
func definitionsAge(dirs []string) (time.Duration, error) {
	var newest time.Time
	for _, dir := range dirs {
		for _, name := range []string{"daily.cld", "daily.cvd", "main.cld", "main.cvd"} {
			if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	if newest.IsZero() {
		return 0, fmt.Errorf("no virus definition files found")
	}
	return time.Since(newest), nil
}

// Get the users home directory
func getHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting home directory: %w", err)
	}
	return home, nil
}

// Check that the infected directory exists and create it if it doesn't,
// returning its path so it is resolved once for the whole run.
func checkInfectedDir() (string, error) {
	home, err := getHomeDir()
	if err != nil {
		return "", err
	}

	infectedDir := filepath.Join(home, "infected")
	if _, err := os.Stat(infectedDir); os.IsNotExist(err) {
		fmt.Println(yellow("[*]"), "Creating infected directory:", infectedDir)
		if err := os.Mkdir(infectedDir, 0755); err != nil {
			return "", fmt.Errorf("error creating infected directory: %w", err)
		}
	} else {
		// Using green for a successful message
		fmt.Println(green("[+]"), "Infected directory ready")
	}
	return infectedDir, nil
}

// create a function to get how many cores are available on the system and set the number of threads to half of that number
func getThreads() int {
	if *concurrency > 0 {
		return *concurrency
	}

	cores := runtime.NumCPU() / 2
	if cores < 1 {
		cores = 1
	}
	fmt.Println("Number of CPU cores:", runtime.NumCPU())
	fmt.Println("Number of threads to use:", cores)
	fmt.Println()
	return cores
}

// quarantine moves an infected file into the quarantine directory, adding
// a numeric suffix instead of overwriting an existing entry and falling
// back to copy+delete when the rename crosses filesystems.
func quarantine(file, dir string) (string, error) {
	base := filepath.Base(file)
	dest := filepath.Join(dir, base)
	for i := 1; ; i++ {
		if _, err := os.Lstat(dest); os.IsNotExist(err) {
			break
		}
		dest = filepath.Join(dir, fmt.Sprintf("%s.%d", base, i))
	}

	if err := os.Rename(file, dest); err == nil {
		return dest, nil
	}

	in, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dest)
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(file); err != nil {
		return "", fmt.Errorf("copied to %s but failed to remove original: %w", dest, err)
	}
	return dest, nil
}

// discoveryStats counts files that were seen but not queued for scanning,
// so coverage is visible instead of silent.
type discoveryStats struct {
	Unreadable int // walk errors / stat failures
	NonRegular int // FIFOs, sockets, devices, symlinks
	Empty      int // zero-byte files
	Hidden     int // skipped via -skip-hidden
	TooLarge   int // over -max-size
	Filtered   int // excluded by -include/-exclude
}

// Total returns how many files were skipped for any reason.
func (s discoveryStats) Total() int {
	return s.Unreadable + s.NonRegular + s.Empty + s.Hidden + s.TooLarge + s.Filtered
}

// String renders only the non-zero skip reasons.
func (s discoveryStats) String() string {
	var parts []string
	add := func(n int, label string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	add(s.Unreadable, "unreadable")
	add(s.NonRegular, "non-regular")
	add(s.Empty, "empty")
	add(s.Hidden, "hidden")
	add(s.TooLarge, "over max-size")
	add(s.Filtered, "extension-filtered")
	return strings.Join(parts, ", ")
}

// findFilesToScan returns a list of files to scan from all directories,
// never descending into the quarantine directory. It uses WalkDir so
// directory entries come without a stat; files are only stat'ed after the
// cheap name-based filters pass.
func findFilesToScan(dirs []string, infectedDir string) ([]string, discoveryStats, error) {
	var allFiles []string
	var stats discoveryStats
	maxSizeBytes := *maxFileSize * 1024 * 1024 // Convert MB to bytes

	// Pre-compile extension maps for faster lookups
	includeMap := make(map[string]bool, len(includeExt))
	for _, ext := range includeExt {
		includeMap[strings.ToLower(ext)] = true
		includeMap["."+strings.ToLower(ext)] = true
	}

	excludeMap := make(map[string]bool, len(excludeExt))
	for _, ext := range excludeExt {
		excludeMap[strings.ToLower(ext)] = true
		excludeMap["."+strings.ToLower(ext)] = true
	}

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				stats.Unreadable++
				return nil // Skip files we can't access
			}

			// Skip directories (we'll scan their contents)
			if d.IsDir() {
				// Never scan the quarantine directory itself
				if abs, err := filepath.Abs(path); err == nil && abs == infectedDir {
					return filepath.SkipDir
				}
				// Skip hidden directories if requested
				if *skipHidden && strings.HasPrefix(filepath.Base(path), ".") {
					return filepath.SkipDir
				}
				return nil
			}

			// Cheap name-based filters first - no stat needed
			if *skipHidden && strings.HasPrefix(filepath.Base(path), ".") {
				stats.Hidden++
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if len(includeMap) > 0 && !includeMap[ext] {
				stats.Filtered++
				return nil
			}
			if len(excludeMap) > 0 && excludeMap[ext] {
				stats.Filtered++
				return nil
			}

			// Only scan regular files - FIFOs, sockets, and device nodes
			// would block the scanner indefinitely. The type bits come
			// from the directory entry, still no stat.
			if !d.Type().IsRegular() {
				stats.NonRegular++
				return nil
			}

			// Stat only the survivors, for the size checks
			info, err := d.Info()
			if err != nil {
				stats.Unreadable++
				return nil
			}

			// Nothing to scan in an empty file
			if info.Size() == 0 {
				stats.Empty++
				return nil
			}

			// Skip files over max size
			if maxSizeBytes > 0 && info.Size() > maxSizeBytes {
				stats.TooLarge++
				if *verbose {
					fmt.Printf("Skipping large file: %s (%.2f MB)\n", path, float64(info.Size())/(1024*1024))
				}
				return nil
			}

			allFiles = append(allFiles, path)
			return nil
		})

		if err != nil {
			return nil, stats, err
		}
	}

	return allFiles, stats, nil
}

// scanWithClamd scans one file over an established clamd connection - no
// subprocess and no per-file reconnect.
func scanWithClamd(client *clamd.Client, file string) ScanResult {
	absFile, err := filepath.Abs(file)
	if err != nil {
		absFile = file // fallback to original
	}

	res, err := client.Scan(absFile)
	if err != nil {
		return ScanResult{
			File:    file,
			IsClean: false,
			Message: res.Raw,
			Error:   err,
		}
	}

	sr := ScanResult{File: file, IsClean: res.Clean}
	// Only keep the raw reply when it matters; clean output is never
	// printed and would just hold buffers alive in the result channel.
	if !res.Clean {
		sr.Message = res.Raw
	}
	return sr
}

type verdict int

const (
	verdictClean verdict = iota
	verdictInfected
	verdictError
)

// parseClamscanLine classifies one line of clamscan output. Verdict lines
// look like "/path: OK", "/path: Sig FOUND", or "/path: msg ERROR";
// anything else (move notices, warnings) is not a per-file verdict.
func parseClamscanLine(line string) (file string, v verdict, ok bool) {
	switch {
	case strings.HasSuffix(line, ": OK"):
		return strings.TrimSuffix(line, ": OK"), verdictClean, true
	case strings.HasSuffix(line, " FOUND"):
		if i := strings.LastIndex(line, ": "); i != -1 {
			return line[:i], verdictInfected, true
		}
	case strings.HasSuffix(line, " ERROR"):
		if i := strings.LastIndex(line, ": "); i != -1 {
			return line[:i], verdictError, true
		}
	}
	return "", 0, false
}

// runClamscanBatch scans a chunk of files with a single clamscan process
// via --file-list, so the signature database loads once per process instead
// of once per file. Per-file results stream to the results channel as
// clamscan prints them. Quarantine is handled in Go by the result
// processor, identically for clamscan and clamd modes.
func runClamscanBatch(ctx context.Context, files []string, results chan<- ScanResult) error {
	listFile, err := os.CreateTemp("", "go-clam-list-*.txt")
	if err != nil {
		return fmt.Errorf("creating file list: %w", err)
	}
	defer os.Remove(listFile.Name())

	for _, f := range files {
		if _, err := fmt.Fprintln(listFile, f); err != nil {
			listFile.Close()
			return fmt.Errorf("writing file list: %w", err)
		}
	}
	if err := listFile.Close(); err != nil {
		return fmt.Errorf("closing file list: %w", err)
	}

	args := []string{
		"--no-summary",
		"--scan-mail=yes",
		"--scan-pdf=yes",
		"--scan-html=yes",
		"--scan-archive=yes",
		"--phishing-scan-urls=yes",
		"--file-list=" + listFile.Name(),
	}
	// Align the engine's own limits with -max-size: stock ClamAV caps
	// scanning at ~25MB, silently reporting bigger accepted files clean
	// after a partial scan. clamscan rejects values above 4000M.
	limitMB := *maxFileSize
	if limitMB <= 0 || limitMB > 4000 {
		limitMB = 4000
	}
	args = append(args,
		fmt.Sprintf("--max-filesize=%dM", limitMB),
		fmt.Sprintf("--max-scansize=%dM", limitMB),
	)

	cmd := exec.CommandContext(ctx, *clamscanPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		file, v, ok := parseClamscanLine(line)
		if !ok {
			continue
		}
		result := ScanResult{File: file, IsClean: v == verdictClean}
		if v != verdictClean {
			result.Message = line
		}
		if v == verdictError {
			result.Error = fmt.Errorf("clamscan: %s", line)
		}
		select {
		case results <- result:
		case <-ctx.Done():
			cmd.Wait()
			return ctx.Err()
		}
	}

	err = cmd.Wait()
	// Exit code 1 just means infections were found; they were already
	// reported line by line.
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("clamscan failed: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// splitChunks divides files into at most n roughly equal chunks.
func splitChunks(files []string, n int) [][]string {
	if n > len(files) {
		n = len(files)
	}
	chunks := make([][]string, 0, n)
	for i := 0; i < n; i++ {
		start := i * len(files) / n
		end := (i + 1) * len(files) / n
		if start < end {
			chunks = append(chunks, files[start:end])
		}
	}
	return chunks
}

func main() {
	flag.Parse()

	// -include already restricts scanning to the listed extensions, so a
	// simultaneous -exclude can never remove anything further; reject the
	// combination instead of silently ignoring one of them.
	if len(includeExt) > 0 && len(excludeExt) > 0 {
		logger.Fatalf("-include and -exclude cannot be used together")
	}

	// Validate directory input
	if len(dirs) == 0 {
		// If no directories specified, use current directory
		dirs = append(dirs, ".")
	}

	// Validate all directories exist
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.Fatalf("Directory %s does not exist", dir)
		}
	}

	// If using clamd, verify the daemon is actually answering on the socket
	if *useClamd {
		client, err := clamd.Dial(*clamdSocket)
		if err != nil {
			logger.Fatalf("Cannot connect to clamd at %s: %v. Please ensure clamd is running or specify correct socket path with -socket", *clamdSocket, err)
		}
		if err := client.Ping(); err != nil {
			client.Close()
			logger.Fatalf("clamd at %s did not answer PING: %v", *clamdSocket, err)
		}
		client.Close()
		fmt.Println(yellow("[*]"), "Using clamd socket at:", *clamdSocket)
		// clamd's limits come from clamd.conf, not from our flags
		if *maxFileSize == 0 || *maxFileSize > 25 {
			fmt.Println(yellow("[*]"), "Note: clamd's MaxFileSize/MaxScanSize (clamd.conf, default ~25MB) still apply - larger files may be only partially scanned")
		}
	}

	// Create infected directory if it doesn't exist
	infectedDir, err := checkInfectedDir()
	if err != nil {
		logger.Fatalf("Failed to check infected directory: %v", err)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Println("Received termination signal. Cleaning up...")
		cancel()
	}()

	// Update virus definitions only when they are stale (>24h) or when
	// -update forces it; -fast skips the check entirely unless forced.
	if *forceUpdate || !*fastMode {
		runUpdate := *forceUpdate
		if !runUpdate {
			if age, err := definitionsAge(clamavDBDirs); err != nil {
				// Can't find the definitions - let freshclam sort it out
				runUpdate = true
			} else if age > 24*time.Hour {
				fmt.Println(yellow("[*]"), "Virus definitions are", age.Round(time.Hour), "old")
				runUpdate = true
			} else {
				fmt.Println(green("[+]"), "Virus definitions are fresh ("+age.Round(time.Minute).String()+" old), skipping update")
			}
		}

		if runUpdate {
			// run freshclam to update the virus definitions
			fmt.Println(yellow("[*]"), "Updating virus definitions")
			cmd := freshclamCommand(ctx)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(red("[!]"), "Error updating virus definitions:", err.Error())
				fmt.Println(yellow("[*]"), "Continuing with scan using existing definitions")
			} else {
				if *verbose {
					fmt.Println(string(output))
				}
				// New definitions only take effect in the daemon after a
				// reload; without this, clamd keeps scanning with the old DB.
				if *useClamd {
					if c, cerr := clamd.Dial(*clamdSocket); cerr == nil {
						if rerr := c.Reload(); rerr == nil {
							fmt.Println(yellow("[*]"), "clamd is reloading the virus database")
						}
						c.Close()
					}
				}
			}
		}
	}

	// Find all files to scan from the specified directories
	fmt.Println(yellow("[*]"), "Discovering files in directories:", dirs)
	files, skipStats, err := findFilesToScan(dirs, infectedDir)
	if err != nil {
		logger.Fatalf("Error finding files: %v", err)
	}

	numFiles := len(files)
	if numFiles == 0 {
		fmt.Println(yellow("[*]"), "No files found to scan in directories:", dirs)
		if skipStats.Total() > 0 {
			fmt.Println(yellow("[*]"), "Skipped", skipStats.Total(), "files:", skipStats.String())
		}
		os.Exit(0)
	}

	fmt.Println(yellow("[*]"), "Found", numFiles, "files to scan")
	if skipStats.Total() > 0 {
		fmt.Println(yellow("[*]"), "Skipped", skipStats.Total(), "files:", skipStats.String())
	}

	// set the number of threads based on the number of cores available
	maxThreads := getThreads()

	// create a wait group to wait for all the goroutines to finish
	var wg sync.WaitGroup

	// Scan outcome counters, owned by the result processor goroutine and
	// only read after <-processorDone.
	var filesProcessed, cleanCount, infectedCount, errorCount int64

	// Replace the progress bar creation with our new tracker
	progressTracker := display.NewProgressTracker(numFiles, *verbose)

	// Channel for results to avoid console output issues
	resultChan := make(chan ScanResult, maxThreads*4) // Increased buffer

	// Start result processor; processorDone closes once every queued
	// result has been handled, so no output is lost at shutdown.
	processorDone := make(chan struct{})
	go func() {
		defer close(processorDone)
		for result := range resultChan {
			if result.File != "" {
				filesProcessed++
			}
			if result.Error != nil {
				errorCount++
				progressTracker.LogResult("Error scanning: "+result.Error.Error(), false, true)
			} else if result.IsClean {
				cleanCount++
				progressTracker.LogResult("File is clean: "+result.File, true, false)
			} else {
				infectedCount++
				progressTracker.LogResult("File is infected: "+result.File, false, false)
				if *verbose {
					fmt.Println(result.Message)
				}
				// Quarantine in Go so clamscan and clamd modes behave
				// identically.
				if dest, qerr := quarantine(result.File, infectedDir); qerr != nil {
					errorCount++
					progressTracker.LogInfo("Failed to quarantine " + result.File + ": " + qerr.Error())
				} else {
					progressTracker.LogInfo("Quarantined: " + result.File + " -> " + dest)
				}
			}
		}
	}()

	if *useClamd {
		// Worker pool over persistent clamd connections - one connection
		// per worker, no subprocess per file.
		workerPool := make(chan string, maxThreads*2) // File queue

		for i := 0; i < maxThreads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				client, err := clamd.Dial(*clamdSocket)
				if err != nil {
					// Keep draining the queue so the scan completes with
					// visible errors instead of hanging.
					for file := range workerPool {
						select {
						case resultChan <- ScanResult{File: file, Error: fmt.Errorf("connecting to clamd: %w", err)}:
						case <-ctx.Done():
							return
						}
					}
					return
				}
				defer client.Close()

				for file := range workerPool {
					result := scanWithClamd(client, file)
					select {
					case resultChan <- result:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// Feed files to worker pool
		go func() {
			defer close(workerPool)
			for _, file := range files {
				select {
				case workerPool <- file:
				case <-ctx.Done():
					return
				}
			}
		}()
	} else {
		// Batch mode: split the file list across a few clamscan processes.
		// Each process loads the signature database once for its whole
		// chunk instead of once per file.
		chunks := splitChunks(files, maxThreads)
		fmt.Println(yellow("[*]"), "Starting", len(chunks), "clamscan batch(es); each loads the virus database once")

		for _, chunk := range chunks {
			chunk := chunk
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runClamscanBatch(ctx, chunk, resultChan); err != nil && ctx.Err() == nil {
					select {
					case resultChan <- ScanResult{Error: err}:
					case <-ctx.Done():
					}
				}
			}()
		}
	}

	// Wait for all workers to complete, then for the result processor to
	// drain every queued result.
	wg.Wait()
	close(resultChan)
	<-processorDone

	// Show final statistics
	progressTracker.Finish(filesProcessed, cleanCount, infectedCount, errorCount)

	// Follow the clamscan exit-code convention so cron/CI can react:
	// 0 = clean, 1 = infections found, 2 = errors occurred.
	switch {
	case infectedCount > 0:
		os.Exit(1)
	case errorCount > 0:
		os.Exit(2)
	}
}
