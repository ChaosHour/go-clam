package clamd

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseSessionReply(t *testing.T) {
	tests := []struct {
		in     string
		id     int
		body   string
		wantOK bool
	}{
		{"1: /tmp/file: OK", 1, "/tmp/file: OK", true},
		{"42: /tmp/eicar: Eicar-Signature FOUND", 42, "/tmp/eicar: Eicar-Signature FOUND", true},
		{"PONG", 0, "PONG", false},
		{"/no/session/prefix: OK", 0, "/no/session/prefix: OK", false},
		{"0: bogus", 0, "0: bogus", false},
	}
	for _, tt := range tests {
		id, body, ok := parseSessionReply(tt.in)
		if id != tt.id || body != tt.body || ok != tt.wantOK {
			t.Errorf("parseSessionReply(%q) = (%d, %q, %v), want (%d, %q, %v)",
				tt.in, id, body, ok, tt.id, tt.body, tt.wantOK)
		}
	}
}

// fakeClamd serves one IDSESSION per connection on a Unix socket. reply
// maps a request id and scanned path to the raw replies to send back, so
// tests can mimic clamd quirks such as duplicate ERROR lines.
func fakeClamd(t *testing.T, reply func(id int, path string) []string) string {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes on macOS, so stay out of
	// the long t.TempDir() path.
	dir, err := os.MkdirTemp("", "clamd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				id := 0
				for {
					cmd, err := br.ReadString(0)
					if err != nil {
						return
					}
					cmd = strings.TrimSuffix(strings.TrimPrefix(cmd, "z"), "\x00")
					var lines []string
					switch {
					case cmd == "IDSESSION":
						continue
					case cmd == "END":
						return
					case cmd == "PING":
						id++
						lines = []string{"PONG"}
					case strings.HasPrefix(cmd, "SCAN "):
						id++
						lines = reply(id, strings.TrimPrefix(cmd, "SCAN "))
					}
					for _, l := range lines {
						conn.Write([]byte(strconv.Itoa(id) + ": " + l + "\x00"))
					}
				}
			}(conn)
		}
	}()
	return sock
}

// clamd 1.5 answers a SCAN of an unreadable file with two ERROR replies.
// The duplicate must not be taken as the verdict for the next file.
func TestScanSkipsDuplicateReplies(t *testing.T) {
	sock := fakeClamd(t, func(id int, path string) []string {
		switch filepath.Base(path) {
		case "noperm":
			return []string{
				path + ": File path check failure: Permission denied. ERROR",
				path + ": Access denied. ERROR",
			}
		case "eicar":
			return []string{path + ": Eicar-Signature FOUND"}
		}
		return []string{path + ": OK"}
	})

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	if _, err := c.Scan("/d/noperm"); err == nil {
		t.Error("noperm: expected an error")
	}
	if _, err := c.Scan("/d/noperm"); err == nil {
		t.Error("second noperm: expected an error")
	}
	res, err := c.Scan("/d/eicar")
	if err != nil || res.Clean || res.Virus != "Eicar-Signature" {
		t.Errorf("eicar: got clean=%v virus=%q err=%v", res.Clean, res.Virus, err)
	}
	for _, f := range []string{"/d/a", "/d/b"} {
		res, err := c.Scan(f)
		if err != nil || !res.Clean {
			t.Errorf("%s: got clean=%v virus=%q err=%v", f, res.Clean, res.Virus, err)
		}
	}
}

// A reply naming a different file must never become this file's verdict.
func TestScanRejectsMismatchedPath(t *testing.T) {
	sock := fakeClamd(t, func(id int, path string) []string {
		if filepath.Base(path) == "victim" {
			return []string{"/d/other: Eicar-Signature FOUND"}
		}
		return []string{path + ": OK"}
	})

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	res, err := c.Scan("/d/victim")
	if err == nil || res.Virus != "" {
		t.Errorf("victim: expected a mismatch error, got virus=%q err=%v", res.Virus, err)
	}
	// The client reconnects and keeps working afterwards
	if res, err := c.Scan("/d/a"); err != nil || !res.Clean {
		t.Errorf("after mismatch: got clean=%v err=%v", res.Clean, err)
	}
}

// A reply ahead of the request id means the session is out of step.
func TestScanRejectsFutureRequestID(t *testing.T) {
	sock := fakeClamd(t, func(id int, path string) []string {
		return []string{path + ": OK"}
	})
	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.lastID = -5 // pretend we lost track; server replies with id 1
	if _, err := c.command("SCAN /d/a"); err == nil {
		t.Error("expected an error for a reply id ahead of the request")
	}
}

func TestParseReply(t *testing.T) {
	res, err := parseReply("/tmp/file: OK")
	if err != nil || !res.Clean {
		t.Errorf("OK reply: got clean=%v err=%v", res.Clean, err)
	}

	res, err = parseReply("/tmp/eicar: Eicar-Signature FOUND")
	if err != nil || res.Clean || res.Virus != "Eicar-Signature" {
		t.Errorf("FOUND reply: got clean=%v virus=%q err=%v", res.Clean, res.Virus, err)
	}

	// Path containing ": " must not confuse signature extraction
	res, err = parseReply("/tmp/odd: name/file: Eicar-Signature FOUND")
	if err != nil || res.Virus != "Eicar-Signature" {
		t.Errorf("FOUND reply with odd path: got virus=%q err=%v", res.Virus, err)
	}

	if _, err = parseReply("/tmp/file: Permission denied ERROR"); err == nil {
		t.Error("ERROR reply: expected an error, got nil")
	}

	if _, err = parseReply("garbage"); err == nil {
		t.Error("unknown reply: expected an error, got nil")
	}
}
