// A wrapper for ClamAV

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

// define the flags
var (
	dir           = flag.String("d", "", "Directory to scan")
	clamscanPath  = flag.String("clamscan", "clamscan", "Path to clamscan binary")
	freshclamPath = flag.String("freshclam", "freshclam", "Path to freshclam binary")
)

// define the colors
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
)

// define freshclam function and print the output to the console
func freshclamCommand() *exec.Cmd {
	cmd := exec.Command(*freshclamPath, "-v")
	return cmd
}

// Get the users home directory
func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error getting home directory: %v", err)
	}
	return home
}

// define the clamscan command
func clamscanCommand(file string) *exec.Cmd {
	return exec.Command(*clamscanPath, "-r", "--no-summary", "--scan-mail=yes", "--scan-pdf=yes", "--scan-html=yes", "--scan-archive=yes", "--phishing-scan-urls=yes", "--exclude-dir="+getHomeDir()+"/infected", "--move="+getHomeDir()+"/infected", file)
}

// create a function to get how many cores are available on the system and set the number of threads to half of that number
func getThreads() int {
	cores := runtime.NumCPU() / 2
	if cores < 1 {
		cores = 1
	}
	fmt.Println("Number of CPU cores:", runtime.NumCPU())
	fmt.Println("Number of threads to use:", cores)
	return cores
}

func main() {
	flag.Parse()

	// run freshclam to update the virus definitions. Don't print the output to the console
	fmt.Println(yellow("[*]"), "Updating virus definitions")
	cmd := freshclamCommand()
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(red("[!]"), "Error:", err.Error())
	} else {
		fmt.Println(string(output))
	}

	// change the current working directory to the directory to scan
	if *dir != "" {
		err := os.Chdir(*dir)
		if err != nil {
			fmt.Println(red("[!]"), "Error changing directory:", err.Error())
			os.Exit(1)
		}
	}

	// get the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println(red("[!]"), "Error getting current working directory:", err.Error())
		os.Exit(1)
	}

	// get the list of files in the directory
	files, err := filepath.Glob("*")
	if err != nil {
		fmt.Println(red("[!]"), "Error:", err.Error())
		os.Exit(1)
	}

	numFiles := len(files)

	fmt.Println(yellow("[*]"), "Scanning directory:", cwd)
	fmt.Println(yellow("[*]"), "Found", numFiles, "files")

	// set the number of threads based on the number of cores available
	maxThreads := getThreads()

	// set the batch size to 1000 files
	batchSize := 1000

	// create a wait group to wait for all the goroutines to finish
	var wg sync.WaitGroup

	// create a progress bar
	bar := progressbar.Default(int64(numFiles))

	// process files in batches
	for i := 0; i < numFiles; i += batchSize {
		// create a channel with a buffer size of maxThreads
		fileChan := make(chan string, maxThreads)

		// start the worker pool
		for j := 0; j < maxThreads; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for file := range fileChan {
					// run clamscan on the file
					cmd := clamscanCommand(file)
					output, err := cmd.CombinedOutput()
					if err != nil {
						fmt.Println(red("[!]"), "Error:", err.Error())
					} else {
						fmt.Println(green("[+]"), "Virus scan completed successfully")
						// print the progress
						fmt.Println()
						fmt.Println()
						bar.Add(1)
						fmt.Println()
						fmt.Println()
						fmt.Printf(yellow("[*] Scanning file %s\n"), file)

						// print the scan results
						if cmd.ProcessState.ExitCode() == 0 {
							fmt.Println(green("[+]"), "File is ok")
							fmt.Println(string(output))
						} else if cmd.ProcessState.ExitCode() == 1 {
							fmt.Println(red("[-]"), "File is infected")
							fmt.Println(string(output))
						} else {
							fmt.Println(red("[!]"), "Unknown exit code:", cmd.ProcessState.ExitCode())
						}
					}
				}
			}()
		}

		// send files to the worker pool
		end := i + batchSize
		if end > numFiles {
			end = numFiles
		}
		for _, file := range files[i:end] {
			fileChan <- file
		}
		close(fileChan)

		// wait for all the goroutines to finish
		wg.Wait()

		// print message indicating that the batch has completed
		fmt.Println(yellow("[*]"), "Finished scanning batch", (i/batchSize)+1, "of", (numFiles/batchSize)+1, "batches")
	}

	fmt.Println(yellow("[*]"), "Finished scanning directory")
}
