package pool

import (
	"sync"
)

// ScanResult represents the outcome of scanning a file
type ScanResult struct {
	File    string
	IsClean bool
	Message string
	Error   error
}

var scanResultPool = sync.Pool{
	New: func() interface{} {
		return &ScanResult{}
	},
}

// GetScanResult returns a ScanResult from the pool
func GetScanResult() *ScanResult {
	return scanResultPool.Get().(*ScanResult)
}

// PutScanResult returns a ScanResult to the pool
func PutScanResult(sr *ScanResult) {
	// Reset fields
	sr.File = ""
	sr.IsClean = false
	sr.Message = ""
	sr.Error = nil
	scanResultPool.Put(sr)
}
