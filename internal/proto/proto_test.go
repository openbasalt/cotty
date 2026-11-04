package proto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameData, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&buf, Request{ID: 1, Op: "state"}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil || f.Type != FrameData || string(f.Payload) != "hello" {
		t.Fatalf("data frame: %+v %v", f, err)
	}
	f, err = ReadFrame(&buf)
	if err != nil || f.Type != FrameJSON {
		t.Fatalf("json frame: %+v %v", f, err)
	}
	var r Request
	if err := json.Unmarshal(f.Payload, &r); err != nil || r.Op != "state" {
		t.Fatalf("decode: %+v %v", r, err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestFrameLimits(t *testing.T) {
	if err := WriteFrame(io.Discard, FrameData, make([]byte, MaxFrame)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
	// A header announcing more than MaxFrame is refused before reading.
	if _, err := ReadFrame(bytes.NewReader([]byte{0x7f, 0, 0, 0, 'j'})); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized read: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("zero length: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 9, 'd', 1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated: %v", err)
	}
}

// TestClient checks request multiplexing, errors, events and data.
func TestClient(t *testing.T) {
	a, b := net.Pipe()
	cl := NewClient(a)
	defer cl.Close()
	go func() {
		for {
			f, err := ReadFrame(b)
			if err != nil {
				return
			}
			if f.Type == FrameData {
				_ = WriteFrame(b, FrameData, append([]byte("echo:"), f.Payload...))
				continue
			}
			var r Request
			_ = json.Unmarshal(f.Payload, &r)
			_ = WriteJSON(b, Event{Event: EventState, Data: map[string]int{"n": 1}})
			if r.Op == "fail" {
				_ = WriteJSON(b, Response{ID: r.ID, Error: &Error{Code: ErrKeyboardHeld}})
				continue
			}
			_ = WriteJSON(b, Response{ID: r.ID, OK: true, Result: map[string]string{"op": r.Op}})
		}
	}()
	var res map[string]string
	if err := cl.Call(context.Background(), "screen", nil, &res); err != nil || res["op"] != "screen" {
		t.Fatalf("call: %v %v", res, err)
	}
	err := cl.Call(context.Background(), "fail", nil, nil)
	if ErrorCode(err) != ErrKeyboardHeld {
		t.Fatalf("error code: %v", err)
	}
	if ev := <-cl.Events(); ev.Event != EventState {
		t.Fatalf("event: %+v", ev)
	}
	if err := cl.SendData([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if d := <-cl.Data(); string(d) != "echo:x" {
		t.Fatalf("data: %q", d)
	}
}
