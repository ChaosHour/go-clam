// Package clamd implements a minimal client for the clamd Unix-socket
// protocol, replacing per-file clamdscan subprocesses with persistent
// connections.
package clamd

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Client is a single clamd connection running an IDSESSION. It is not safe
// for concurrent use; give each worker its own Client.
type Client struct {
	socketPath string
	conn       net.Conn
	br         *bufio.Reader
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
	return nil
}

// command sends one null-terminated command and reads the single reply.
func (c *Client) command(cmd string) (string, error) {
	if _, err := c.conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", err
	}
	reply, err := c.br.ReadString(0)
	if err != nil {
		return "", err
	}
	return stripSessionID(strings.TrimSuffix(reply, "\x00")), nil
}

// Ping checks that clamd is alive and answering on the socket.
func (c *Client) Ping() error {
	reply, err := c.command("PING")
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("unexpected clamd reply to PING: %q", reply)
	}
	return nil
}

// Scan asks clamd to scan the file at path (must be absolute and readable
// by the clamd process). If the session was dropped (idle timeout, daemon
// reload), it reconnects once before giving up.
func (c *Client) Scan(path string) (Result, error) {
	reply, err := c.command("SCAN " + path)
	if err != nil {
		c.Close()
		if rerr := c.connect(); rerr != nil {
			return Result{}, err
		}
		reply, err = c.command("SCAN " + path)
		if err != nil {
			return Result{}, err
		}
	}
	return parseReply(reply)
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

// stripSessionID removes the "<request-id>: " prefix clamd adds to every
// reply inside an IDSESSION.
func stripSessionID(reply string) string {
	if i := strings.Index(reply, ": "); i > 0 {
		if _, err := strconv.Atoi(reply[:i]); err == nil {
			return reply[i+2:]
		}
	}
	return reply
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
