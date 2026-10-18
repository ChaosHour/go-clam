// Package clamd implements a minimal client for the clamd Unix-socket
// protocol, replacing per-file clamdscan subprocesses with persistent
// connections.
package clamd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Client is a single clamd connection running an IDSESSION. It is not safe
// for concurrent use; give each worker its own Client.
type Client struct {
	socketPath string
	conn       net.Conn
	br         *bufio.Reader
	lastID     int // request id of the most recent command in this session
}

// Result is the outcome of scanning one path.
type Result struct {
	Clean bool
	Virus string // signature name when not clean
	Raw   string // full clamd reply line
}

// Dial connects to the clamd Unix socket and starts an IDSESSION.
func Dial(socketPath string) (*Client, error) {
	c := &Client{socketPath: socketPath}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) connect() error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return err
	}
	if _, err := conn.Write([]byte("zIDSESSION\x00")); err != nil {
		conn.Close()
		return err
	}
	c.conn = conn
	c.br = bufio.NewReader(conn)
	c.lastID = 0
	return nil
}

// command sends one null-terminated command and returns the reply carrying
// its request id. When f is non-nil its descriptor follows the command as
// SCM_RIGHTS ancillary data, as FILDES expects. clamd numbers the commands of an IDSESSION from 1, and
// can send more than one reply for a single request: clamd 1.5 answers a
// SCAN of an unreadable or vanished file with two ERROR lines. Replies for
// earlier requests are therefore discarded rather than taken as this
// command's answer. Without that, one stray reply would shift every later
// verdict on the connection onto the wrong file.
func (c *Client) command(cmd string, f *os.File) (string, error) {
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return "", err
		}
	}
	c.lastID++
	want := c.lastID
	if _, err := c.conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", err
	}
	if f != nil {
		uc, ok := c.conn.(*net.UnixConn)
		if !ok {
			return "", fmt.Errorf("descriptor passing needs a Unix socket")
		}
		// clamd reads one dummy byte that carries the descriptor
		if _, _, err := uc.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd())), nil); err != nil {
			return "", err
		}
	}
	for {
		reply, err := c.br.ReadString(0)
		if err != nil {
			return "", err
		}
		id, body, ok := parseSessionReply(strings.TrimSuffix(reply, "\x00"))
		switch {
		case !ok:
			return "", fmt.Errorf("clamd reply without request id: %q", reply)
		case id < want:
			continue // late duplicate of an earlier request
		case id > want:
			return "", fmt.Errorf("clamd reply for request %d while waiting for %d", id, want)
		}
		return body, nil
	}
}

// Ping checks that clamd is alive and answering on the socket.
func (c *Client) Ping() error {
	reply, err := c.command("PING", nil)
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("unexpected clamd reply to PING: %q", reply)
	}
	return nil
}

// Reload asks clamd to reload the virus database, so freshly downloaded
// definitions take effect without restarting the daemon.
func (c *Client) Reload() error {
	reply, err := c.command("RELOAD", nil)
	if err != nil {
		return err
	}
	if reply != "RELOADING" {
		return fmt.Errorf("unexpected clamd reply to RELOAD: %q", reply)
	}
	return nil
}

// Scan asks clamd to scan the file at path (must be absolute and readable
// by the clamd process). If the session was dropped (idle timeout, daemon
// reload) or got out of step, it reconnects once before giving up. A
// verdict is only returned when the reply names path itself, so a reply
// can never be attributed to a different file.
func (c *Client) Scan(path string) (Result, error) {
	reply, err := c.retry("SCAN "+path, nil)
	if err != nil {
		return Result{}, err
	}
	if !strings.HasPrefix(reply, path+": ") {
		c.Close()
		return Result{Raw: reply}, fmt.Errorf("clamd reply does not match scanned file: %q", reply)
	}
	return parseReply(reply)
}

// ScanFile opens path itself and passes the open descriptor to clamd
// (FILDES), so clamd scans whatever this process can read. That covers
// files clamd cannot open on its own, such as those behind macOS privacy
// protection (~/Library/Mail, ~/Library/Messages, ...) when the daemon
// lacks Full Disk Access. An open failure is reported without contacting
// clamd. Verdicts are returned with the "fd[N]" clamd puts in place of a
// file name replaced by path.
func (c *Client) ScanFile(path string) (Result, error) {
	// O_NONBLOCK keeps a file swapped for a FIFO since discovery from
	// blocking the open; it has no effect on regular files.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	reply, err := c.retry("FILDES", f)
	if err != nil {
		return Result{}, err
	}
	i := strings.Index(reply, "]: ")
	if !strings.HasPrefix(reply, "fd[") || i == -1 {
		c.Close()
		return Result{Raw: reply}, fmt.Errorf("unexpected clamd reply to FILDES: %q", reply)
	}
	return parseReply(path + reply[i+1:])
}

// retry runs a scan command, reconnecting once if the session was dropped
// (idle timeout, daemon reload) or got out of step. The connection is
// closed after a second failure so the next call starts a fresh session.
func (c *Client) retry(cmd string, f *os.File) (string, error) {
	reply, err := c.command(cmd, f)
	if err == nil {
		return reply, nil
	}
	c.Close()
	if rerr := c.connect(); rerr != nil {
		return "", err
	}
	reply, err = c.command(cmd, f)
	if err != nil {
		c.Close()
		return "", err
	}
	return reply, nil
}

// Close ends the session and closes the connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	c.conn.Write([]byte("zEND\x00"))
	err := c.conn.Close()
	c.conn = nil
	return err
}

// parseSessionReply splits the "<request-id>: " prefix clamd adds to every
// reply inside an IDSESSION from the reply body. ok is false when the
// prefix is missing.
func parseSessionReply(reply string) (id int, body string, ok bool) {
	i := strings.Index(reply, ": ")
	if i <= 0 {
		return 0, reply, false
	}
	id, err := strconv.Atoi(reply[:i])
	if err != nil || id <= 0 {
		return 0, reply, false
	}
	return id, reply[i+2:], true
}

// parseReply classifies a clamd verdict line: "path: OK",
// "path: Signature FOUND", or "path: message ERROR".
func parseReply(reply string) (Result, error) {
	switch {
	case strings.HasSuffix(reply, ": OK"):
		return Result{Clean: true, Raw: reply}, nil
	case strings.HasSuffix(reply, " FOUND"):
		msg := strings.TrimSuffix(reply, " FOUND")
		virus := msg
		if i := strings.LastIndex(msg, ": "); i != -1 {
			virus = msg[i+2:]
		}
		return Result{Virus: virus, Raw: reply}, nil
	case strings.HasSuffix(reply, " ERROR"):
		return Result{Raw: reply}, fmt.Errorf("clamd: %s", reply)
	default:
		return Result{Raw: reply}, fmt.Errorf("unexpected clamd reply: %q", reply)
	}
}
