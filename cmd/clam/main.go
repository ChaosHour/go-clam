// A wrapper for ClamAV

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	flag.Var(&includeExt, "include", "Only scan these file extensions (can be specified multiple times)")
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

// Get the users home directory
func getHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting home directory: %w", err)
	}
	return home, nil
}

// Check that the infected directory exists and create it if it doesn't
func checkInfectedDir() error {
	home, err := getHomeDir()
	if err != nil {
		return err
	}

	infectedDir := filepath.Join(home, "infected")
	if _, err := os.Stat(infectedDir); os.IsNotExist(err) {
		fmt.Println(yellow("[*]"), "Creating infected directory:", infectedDir)
		if err := os.Mkdir(infectedDir, 0755); err != nil {
			return fmt.Errorf("error creating infected directory: %w", err)
		}
	} else {
		// Using green for a successful message
		fmt.Println(green("[+]"), "Infected directory ready")
	}
	return nil
}

func clamscanCommand(ctx context.Context, file string, needsSudo bool) *exec.Cmd {
	home, err := getHomeDir()
	if err != nil {
		logger.Printf("Error getting home directory: %v", err)
		home = "~/infected" // Fallback
	}

	infectedDir := filepath.Join(home, "infected")
	args := []string{
		"-r",
		"--no-summary",
		"--scan-mail=yes",
		"--scan-pdf=yes",
		"--scan-html=yes",
		"--scan-archive=yes",
		"--phishing-scan-urls=yes",
		"--exclude-dir=" + infectedDir,
		"--move=" + infectedDir,
		file,
	}

	if needsSudo {
		return exec.CommandContext(ctx, "sudo", append([]string{*clamscanPath}, args...)...)
	}
	return exec.CommandContext(ctx, *clamscanPath, args...)
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

// findFilesToScan returns a list of files to scan from all directories
func findFilesToScan(dirs []string) ([]string, error) {
	var allFiles []string
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
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip files we can't access
			}

			// Skip directories (we'll scan their contents)
			if info.IsDir() {
				// Skip hidden directories if requested
				if *skipHidden && strings.HasPrefix(filepath.Base(path), ".") {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip hidden files if requested
			if *skipHidden && strings.HasPrefix(filepath.Base(path), ".") {
				return nil
			}

			// Skip files over max size
			if maxSizeBytes > 0 && info.Size() > maxSizeBytes {
				if *verbose {
					fmt.Printf("Skipping large file: %s (%.2f MB)\n", path, float64(info.Size())/(1024*1024))
				}
				return nil
			}

			// Handle extension filtering with pre-compiled maps
			ext := strings.ToLower(filepath.Ext(path))
			if len(includeMap) > 0 && !includeMap[ext] {
				return nil
			}
			if len(excludeMap) > 0 && excludeMap[ext] {
				return nil
			}

			allFiles = append(allFiles, path)
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return allFiles, nil
}

// scanWithClamd uses the ClamAV daemon for scanning which is much faster
func scanWithClamd(ctx context.Context, file string) ScanResult {
	// Use absolute path to avoid relative path resolution overhead
	absFile, err := filepath.Abs(file)
	if err != nil {
		absFile = file // fallback to original
	}

	// Optimized command with minimal options for speed
	cmd := exec.CommandContext(ctx, "clamdscan", "--no-summary", "--quiet", absFile)

	// Use smaller buffer for faster I/O
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if it's just a virus found (exit code 1)
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return ScanResult{
				File:    file,
				IsClean: false,
				Message: string(output),
				Error:   nil,
			}
		}
		return ScanResult{
			File:    file,
			IsClean: false,
			Message: string(output),
			Error:   err,
		}
	}

	return ScanResult{
		File:    file,
		IsClean: true,
		Message: string(output),
		Error:   nil,
	}
}

// scanFile handles the scanning of an individual file and returns the result
func scanFile(ctx context.Context, file string) ScanResult {
	// Use clamd if requested (much faster)
	if *useClamd {
		return scanWithClamd(ctx, file)
	}

	// Check if we need sudo by testing directory permissions
	dir := filepath.Dir(file)
	_, err := os.Stat(dir)
	needsSudo := err != nil && os.IsPermission(err)

	if needsSudo && *verbose {
		fmt.Println(yellow("[*]"), "User does not have permission to access directory:", dir)
		fmt.Println(yellow("[*]"), "Running clamscan with sudo")
	}

	// Create and run the appropriate command with context
	cmd := clamscanCommand(ctx, file, needsSudo)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if it's just a virus found (exit code 1)
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return ScanResult{
				File:    file,
				IsClean: false,
				Message: string(output),
				Error:   nil,
			}
		}
		return ScanResult{
			File:    file,
			IsClean: false,
			Message: string(output),
			Error:   err,
		}
	}

	return ScanResult{
		File:    file,
		IsClean: true,
		Message: string(output),
		Error:   nil,
	}
}

func main() {
	flag.Parse()

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

	// If using clamd, verify the socket exists
	if *useClamd {
		_, err := os.Stat(*clamdSocket)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Fatalf("ClamAV socket not found at %s. Please ensure clamd is running or specify correct socket path with -socket", *clamdSocket)
			} else {
				logger.Fatalf("Error accessing clamd socket at %s: %v", *clamdSocket, err)
			}
		}
		fmt.Println(yellow("[*]"), "Using clamd socket at:", *clamdSocket)
	}

	// Create infected directory if it doesn't exist
	if err := checkInfectedDir(); err != nil {
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

	// Skip virus definition updates in fast mode
	if !*fastMode {
		// run freshclam to update the virus definitions
		fmt.Println(yellow("[*]"), "Updating virus definitions")
		cmd := freshclamCommand(ctx)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(red("[!]"), "Error updating virus definitions:", err.Error())
			fmt.Println(yellow("[*]"), "Continuing with scan using existing definitions")
		} else if *verbose {
			fmt.Println(string(output))
		}
	}

	// Find all files to scan from the specified directories
	fmt.Println(yellow("[*]"), "Discovering files in directories:", dirs)
	files, err := findFilesToScan(dirs)
	if err != nil {
		logger.Fatalf("Error finding files: %v", err)
	}

	numFiles := len(files)
	if numFiles == 0 {
		fmt.Println(yellow("[*]"), "No files found to scan in directories:", dirs)
		os.Exit(0)
	}

	fmt.Println(yellow("[*]"), "Found", numFiles, "files to scan")

	// set the number of threads based on the number of cores available
	maxThreads := getThreads()

	// create a wait group to wait for all the goroutines to finish
	var wg sync.WaitGroup

	// Create atomic counter for progress
	var filesProcessed int64 = 0

	// Replace the progress bar creation with our new tracker
	progressTracker := display.NewProgressTracker(numFiles, *verbose)

	// Channel for results to avoid console output issues
	resultChan := make(chan ScanResult, maxThreads*4) // Increased buffer

	// Start result processor
	go func() {
		for result := range resultChan {
			if result.Error != nil {
				progressTracker.LogResult("Error scanning: "+result.Error.Error(), false, true)
			} else if result.IsClean {
				progressTracker.LogResult("File is clean: "+result.File, true, false)
			} else {
				progressTracker.LogResult("File is infected: "+result.File, false, false)
				if *verbose {
					fmt.Println(result.Message)
				}
			}
		}
	}()

	// Use worker pool pattern for better resource management
	workerPool := make(chan string, maxThreads*2) // File queue

	// Start worker goroutines
	for i := 0; i < maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range workerPool {
				result := scanFile(ctx, file)
				atomic.AddInt64(&filesProcessed, 1)

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

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait a moment for the result processor to finish
	time.Sleep(100 * time.Millisecond)

	// Show final statistics
	progressTracker.Finish(atomic.LoadInt64(&filesProcessed))
}
