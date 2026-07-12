package display

import (
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

// Colors for console output
var (
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
)

// ProgressTracker handles synchronized progress bar updates and output
type ProgressTracker struct {
	Bar         *progressbar.ProgressBar
	Total       int
	OutputMutex sync.Mutex
	Verbose     bool
	StartTime   time.Time
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(total int, verbose bool) *ProgressTracker {
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Scanning files"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{Saucer: "=", SaucerPadding: "-"}),
		// Remove OptionClearOnFinish() to control display manually
	)

	return &ProgressTracker{
		Bar:       bar,
		Total:     total,
		Verbose:   verbose,
		StartTime: time.Now(),
	}
}

// LogResult logs a scan result with proper synchronization
func (pt *ProgressTracker) LogResult(message string, isClean bool, isError bool) {
	pt.OutputMutex.Lock()
	defer pt.OutputMutex.Unlock()

	// Add a newline before output for cleaner display
	if pt.Verbose {
		fmt.Println()
	}

	// Print the result with appropriate color
	if isError {
		fmt.Println(Red("[!]"), message)
	} else if isClean {
		if pt.Verbose {
			fmt.Println(Green("[+]"), message)
		}
	} else {
		fmt.Println(Red("[-]"), message)
	}

	// Update the progress bar; progressbar handles its own render throttling
	pt.Bar.Add(1)
}

// Finish completes the progress tracking and shows final statistics
func (pt *ProgressTracker) Finish(filesScanned, clean, infected, errors int64) {
	pt.OutputMutex.Lock()
	defer pt.OutputMutex.Unlock()

	// Ensure the bar shows 100% completion
	if !pt.Bar.IsFinished() {
		pt.Bar.Set(pt.Total)
	}

	// Now finish and clear the bar
	pt.Bar.Finish()

	// Clear the progress bar line and move to next line
	fmt.Print("\r\033[K\n")

	elapsedTime := time.Since(pt.StartTime)
	fmt.Printf("%s Scan complete. Scanned %d files in %s (%.2f files/sec)\n",
		Green("[+]"), filesScanned, elapsedTime,
		float64(filesScanned)/elapsedTime.Seconds())
	fmt.Printf("    %s: %d   %s: %d   %s: %d\n",
		Green("Clean"), clean, Red("Infected"), infected, Yellow("Errors"), errors)

	fmt.Println() // Extra blank line for spacing
}

// LogInfo logs an informational message without advancing the progress bar
func (pt *ProgressTracker) LogInfo(message string) {
	pt.OutputMutex.Lock()
	defer pt.OutputMutex.Unlock()

	// Clear the current progress bar line and move to a new line
	fmt.Print("\r\033[K")
	fmt.Println(Yellow("[*]"), message)

	// Re-render the progress bar if it's not finished
	if !pt.Bar.IsFinished() {
		pt.Bar.RenderBlank()
	}
}

// LogVerbose logs a message only in verbose mode
func (pt *ProgressTracker) LogVerbose(message string) {
	if !pt.Verbose {
		return
	}
	pt.LogInfo(message)
}
