package clamd

import "testing"

func TestStripSessionID(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1: /tmp/file: OK", "/tmp/file: OK"},
		{"42: /tmp/eicar: Eicar-Signature FOUND", "/tmp/eicar: Eicar-Signature FOUND"},
		{"PONG", "PONG"},
		{"/no/session/prefix: OK", "/no/session/prefix: OK"},
	}
	for _, tt := range tests {
		if got := stripSessionID(tt.in); got != tt.want {
			t.Errorf("stripSessionID(%q) = %q, want %q", tt.in, got, tt.want)
		}
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
