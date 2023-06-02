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
)

// define the flags
var (
	dir           = flag.String("d", "", "Directory to scan")
	clamscanPath  = flag.String("clamscan", "/usr/local/bin/clamscan", "Path to clamscan binary")
	freshclamPath = flag.String("freshclam", "/usr/local/bin/freshclam", "Path to freshclam binary")
)

// define the colors
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
)

// check and make sure the directory exists
func checkDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return err
	}
	return nil
}

// get the list of files in the directory
func getFiles(dir string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "*"))
}

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
	// return exec.Command(*clamscanPath, "--no-summary", file)
	// use the homedir function to get the users home directory and add that as the exclude directory
	return exec.Command(*clamscanPath, "-r", "--no-summary", "--scan-mail=yes", "--scan-pdf=yes", "--scan-html=yes", "--scan-archive=yes", "--phishing-scan-urls=yes", "--exclude-dir="+getHomeDir()+"/infected", "--move="+getHomeDir()+"/infected", file)

}

// create a function to get how many cores are available on the system and set the number of threads to half of that number
func getThreads() int {
	cores := runtime.NumCPU() / 2
	if cores < 1 {
		cores = 1
	}
	return cores
}

func main() {
	flag.Parse()

	if err := checkDir(*dir); err != nil {
		fmt.Println(red("[!]"), "Error:", err.Error())
		os.Exit(1)
	}

	fmt.Println(blue("[*]"), ("Running freshclam"))
	cmd := freshclamCommand()
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running freshclam: %v", err)
	}

	// get the list of files in the directory
	files, err := getFiles(*dir)
	if err != nil {
		fmt.Println(red("[!]"), "Error:", err.Error())
		os.Exit(1)
	}

	numFiles := len(files)

	fmt.Println(yellow("[*]"), "Scanning directory:", *dir)
	fmt.Println(yellow("[*]"), "Found", numFiles, "files")

	// run the clamscan in parallel
	var wg sync.WaitGroup
	// set the number of threads based on the number of cores available getThreads()
	maxThreads := getThreads()
	threadChan := make(chan struct{}, maxThreads)

	// create the sync.Map
	results := new(sync.Map)

	// loop over each file and execute a clamscan command in a separate goroutine
	for _, file := range files {
		threadChan <- struct{}{}
		wg.Add(1)
		go func(file string) {
			defer func() {
				<-threadChan
				wg.Done()
			}()
			// run clamscan in parallel and print the output to the console
			fmt.Println(blue("[*]"), "Scanning file:", file)
			cmd := clamscanCommand(file)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(red("[!]"), "Error scanning file:", file, "-", err.Error())
			}
			fmt.Println(yellow("[*]"), string(output))
			// add the result to the map
			results.Store(file, string(output))
		}(file)
	}

	wg.Wait()

	// print when the scan has been completed to the console
	fmt.Println(yellow("[*]"), "Finished scanning directory")

}
