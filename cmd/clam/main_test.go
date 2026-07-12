package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestParseClamscanLine(t *testing.T) {
	tests := []struct {
		line     string
		wantFile string
		wantV    verdict
		wantOK   bool
	}{
		{"/tmp/file.txt: OK", "/tmp/file.txt", verdictClean, true},
		{"/tmp/eicar.com: Eicar-Signature FOUND", "/tmp/eicar.com", verdictInfected, true},
		{"/tmp/locked: Access denied. ERROR", "/tmp/locked", verdictError, true},
		{"/tmp/eicar.com: moved to '/home/u/infected/eicar.com'", "", 0, false},
		{"", "", 0, false},
		{"LibClamAV Warning: something", "", 0, false},
	}
	for _, tt := range tests {
		file, v, ok := parseClamscanLine(tt.line)
		if ok != tt.wantOK || file != tt.wantFile || (ok && v != tt.wantV) {
			t.Errorf("parseClamscanLine(%q) = (%q, %v, %v), want (%q, %v, %v)",
				tt.line, file, v, ok, tt.wantFile, tt.wantV, tt.wantOK)
		}
	}
}

func TestSplitChunks(t *testing.T) {
	files := []string{"a", "b", "c", "d", "e"}

	chunks := splitChunks(files, 2)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	if total != len(files) {
		t.Errorf("chunks cover %d files, want %d", total, len(files))
	}

	// More chunks than files must not create empty chunks
	chunks = splitChunks(files, 10)
	if len(chunks) != len(files) {
		t.Errorf("expected %d chunks, got %d", len(files), len(chunks))
	}
	for i, c := range chunks {
		if len(c) == 0 {
			t.Errorf("chunk %d is empty", i)
		}
	}

	if got := splitChunks(nil, 4); len(got) != 0 {
		t.Errorf("expected no chunks for empty input, got %d", len(got))
	}
}

func TestFindFilesToScan(t *testing.T) {
	dir := t.TempDir()
	quarantineDir := filepath.Join(dir, "infected")
	if err := os.Mkdir(quarantineDir, 0755); err != nil {
		t.Fatal(err)
	}

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("scan-me.txt", "content")
	write("empty.txt", "")
	write("infected/sample.bin", "quarantined - must not be rescanned")
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.fifo"), 0644); err != nil {
		t.Fatal(err)
	}

	files, stats, err := findFilesToScan([]string{dir}, quarantineDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "scan-me.txt" {
		t.Errorf("expected only scan-me.txt, got %v", files)
	}
	if stats.Empty != 1 {
		t.Errorf("expected 1 empty skip, got %d", stats.Empty)
	}
	if stats.NonRegular != 1 {
		t.Errorf("expected 1 non-regular skip, got %d", stats.NonRegular)
	}
	if got := stats.Total(); got != 2 {
		t.Errorf("expected 2 total skips, got %d (%s)", got, stats)
	}
}

func TestQuarantine(t *testing.T) {
	src := t.TempDir()
	qdir := t.TempDir()

	file := filepath.Join(src, "bad.bin")
	if err := os.WriteFile(file, []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}

	dest, err := quarantine(file, qdir)
	if err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}
	if dest != filepath.Join(qdir, "bad.bin") {
		t.Errorf("unexpected destination: %s", dest)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("original file still exists after quarantine")
	}
	if data, err := os.ReadFile(dest); err != nil || string(data) != "payload" {
		t.Errorf("quarantined content wrong: %q err=%v", data, err)
	}

	// A second file with the same name must get a suffix, not overwrite
	if err := os.WriteFile(file, []byte("payload2"), 0644); err != nil {
		t.Fatal(err)
	}
	dest2, err := quarantine(file, qdir)
	if err != nil {
		t.Fatalf("second quarantine failed: %v", err)
	}
	if dest2 == dest {
		t.Error("second quarantine overwrote the first entry")
	}
	if data, _ := os.ReadFile(dest); string(data) != "payload" {
		t.Error("first quarantined file was modified")
	}
}
