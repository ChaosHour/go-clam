package main

import "testing"

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
