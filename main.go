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
	var files []string
	err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Println(red("[!]"), "Error:", err.Error())
		os.Exit(1)
	}

	numFiles := len(files)

	fmt.Println(yellow("[*]"), "Scanning directory:", cwd)
	fmt.Println(yellow("[*]"), "Found", numFiles, "files")

	// set the number of threads based on the number of cores available
	maxThreads := getThreads()

	// create a channel to send files to the worker pool
	fileChan := make(chan string, numFiles)

	// create a wait group to wait for all the goroutines to finish
	var wg sync.WaitGroup

	// start the worker pool
	for i := 0; i < maxThreads; i++ {
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
					fmt.Printf(yellow("[*] Scanning file %s\n"), file)
					if cmd.ProcessState.ExitCode() == 0 {
						fmt.Println(green("[+]"), "File is ok")
					} else if cmd.ProcessState.ExitCode() == 1 {
						fmt.Println(red("[-]"), "File is infected")
					} else {
						fmt.Println(red("[!]"), "Unknown exit code:", cmd.ProcessState.ExitCode())
					}
					fmt.Println(string(output))
				}
			}
		}()
	}

	// send files to the worker pool
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	// wait for all the goroutines to finish
	wg.Wait()
	fmt.Println(yellow("[*]"), "Finished scanning directory")
}
