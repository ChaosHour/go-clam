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
	Bar          *progressbar.ProgressBar
	Total        int
	Completed    int
	OutputMutex  sync.Mutex
	Verbose      bool
	StartTime    time.Time
	LastUpdateMs int64
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
		Completed: 0,
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

	// Update the progress bar
	pt.Completed++
	pt.Bar.Add(1)

	// Force refresh at most every 100ms to prevent flickering
	now := time.Now().UnixNano() / int64(time.Millisecond)
	if now-pt.LastUpdateMs > 100 {
		pt.LastUpdateMs = now
		pt.Bar.RenderBlank()
	}
}

// Finish completes the progress tracking and shows final statistics
func (pt *ProgressTracker) Finish(filesScanned int64) {
	pt.OutputMutex.Lock()
	defer pt.OutputMutex.Unlock()

	// Ensure the bar shows 100% completion
	if !pt.Bar.IsFinished() {
		pt.Bar.Set(pt.Total)
	}

	// Let the progress bar render one final time at 100%
	time.Sleep(50 * time.Millisecond)

	// Now finish and clear the bar
	pt.Bar.Finish()

	// Clear the progress bar line and move to next line
	fmt.Print("\r\033[K\n")

	elapsedTime := time.Since(pt.StartTime)
	fmt.Printf("%s Scan complete. Scanned %d files in %s (%.2f files/sec)\n",
		Green("[+]"), filesScanned, elapsedTime,
		float64(filesScanned)/elapsedTime.Seconds())

	fmt.Println() // Extra blank line for spacing
}

// LogVerbose logs a message only in verbose mode
func (pt *ProgressTracker) LogVerbose(message string) {
	if !pt.Verbose {
		return
	}

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
