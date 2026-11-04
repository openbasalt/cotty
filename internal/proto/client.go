package proto

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Client is a protocol client: it multiplexes requests by id and hands
// events and data frames to channels. Safe for concurrent use.
type Client struct {
	conn    net.Conn
	wmu     sync.Mutex
	nextID  atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan RawResponse
	events  chan RawResponse
	data    chan []byte
	done    chan struct{}
	err     error
}

// ErrClosed is returned for calls on a closed client.
var ErrClosed = errors.New("proto: connection closed")

// Dial connects to a session socket.
func Dial(path string) (*Client, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient wraps an established connection.
func NewClient(c net.Conn) *Client {
	cl := &Client{
		conn:    c,
		pending: map[int64]chan RawResponse{},
		events:  make(chan RawResponse, 64),
		data:    make(chan []byte, 256),
		done:    make(chan struct{}),
	}
	go cl.readLoop()
	return cl
}

// Events returns the channel of broker events (closed when the
// connection ends).
func (c *Client) Events() <-chan RawResponse { return c.events }

// Data returns the channel of data frames (closed when the connection
// ends).
func (c *Client) Data() <-chan []byte { return c.data }

// Done is closed when the connection ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err is the reason the connection ended.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// PeerCred returns the pid and uid the kernel recorded for the other end
// of the connection (SO_PEERCRED; for a client, the process that called
// listen on the socket).
func (c *Client) PeerCred() (pid, uid int, err error) {
	uc, ok := c.conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("proto: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if cerr != nil {
		return 0, 0, cerr
	}
	return int(cred.Pid), int(cred.Uid), nil
}

// Conn returns the underlying connection.
func (c *Client) Conn() net.Conn { return c.conn }

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) readLoop() {
	defer func() {
		c.mu.Lock()
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.events)
		close(c.data)
		close(c.done)
	}()
	for {
		f, err := ReadFrame(c.conn)
		if err != nil {
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			return
		}
		switch f.Type {
		case FrameData:
			c.data <- f.Payload
		case FrameJSON:
			var r RawResponse
			if json.Unmarshal(f.Payload, &r) != nil {
				continue
			}
			if r.Event != "" {
				select {
				case c.events <- r:
				default:
					// A slow consumer loses events, never responses.
				}
				continue
			}
			c.mu.Lock()
			ch := c.pending[r.ID]
			delete(c.pending, r.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- r
			}
		}
	}
}

// Call sends a request and decodes the result into out (may be nil).
// A failed response is returned as *Error.
func (c *Client) Call(ctx context.Context, op string, args, out any) error {
	id := c.nextID.Add(1)
	req := Request{ID: id, Op: op}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		req.Args = b
	}
	ch := make(chan RawResponse, 1)
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return ErrClosed
	default:
	}
	c.pending[id] = ch
	c.mu.Unlock()
	c.wmu.Lock()
	err := WriteJSON(c.conn, req)
	c.wmu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if !r.OK {
			if r.Error == nil {
				return &Error{Code: ErrInternal}
			}
			return r.Error
		}
		if out != nil && len(r.Result) > 0 {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// SendData sends a data frame (person connections).
func (c *Client) SendData(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return WriteFrame(c.conn, FrameData, b)
}

// Hello performs the hello exchange.
func (c *Client) Hello(ctx context.Context, h Hello) (HelloResult, error) {
	if h.V == 0 {
		h.V = Version
	}
	var r HelloResult
	err := c.Call(ctx, "hello", h, &r)
	return r, err
}

// ErrorCode returns the protocol error code of err, or "".
func ErrorCode(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
