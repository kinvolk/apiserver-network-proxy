/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server/proxystrategies"
)

const writerTestSafetyTimeout = time.Second

type writerTestSentPacket struct {
	typeID    client.PacketType
	connectID int64
}

type writerTestAgentStream struct {
	ctx context.Context

	mu   sync.Mutex
	sent []writerTestSentPacket
}

func newWriterTestBackend(ctx context.Context, agentID string) (*Backend, *writerTestAgentStream) {
	if ctx == nil {
		ctx = context.Background()
	}
	stream := &writerTestAgentStream{ctx: ctx}
	return &Backend{id: agentID, conn: stream}, stream
}

func (s *writerTestAgentStream) Send(pkt *client.Packet) error {
	entry := writerTestSentPacket{typeID: pkt.Type}
	if closeReq := pkt.GetCloseRequest(); closeReq != nil {
		entry.connectID = closeReq.ConnectID
	}
	s.mu.Lock()
	s.sent = append(s.sent, entry)
	s.mu.Unlock()
	return nil
}

func (s *writerTestAgentStream) Recv() (*client.Packet, error) { return nil, io.EOF }
func (s *writerTestAgentStream) SetHeader(metadata.MD) error   { return nil }
func (s *writerTestAgentStream) SendHeader(metadata.MD) error  { return nil }
func (s *writerTestAgentStream) SetTrailer(metadata.MD)        {}
func (s *writerTestAgentStream) Context() context.Context      { return s.ctx }
func (s *writerTestAgentStream) SendMsg(any) error             { return nil }
func (s *writerTestAgentStream) RecvMsg(any) error             { return io.EOF }

func (s *writerTestAgentStream) count(packetType client.PacketType) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, pkt := range s.sent {
		if pkt.typeID == packetType {
			count++
		}
	}
	return count
}

func (s *writerTestAgentStream) closeRequestIDs() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []int64
	for _, pkt := range s.sent {
		if pkt.typeID == client.PacketType_CLOSE_REQ {
			ids = append(ids, pkt.connectID)
		}
	}
	return ids
}

func newWriterTestServer() *ProxyServer {
	return NewProxyServer(
		"",
		[]proxystrategies.ProxyStrategy{proxystrategies.ProxyStrategyDefault},
		1,
		nil,
		1,
	)
}

func writerTestEventually(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(writerTestSafetyTimeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

type writerTestImmediateHTTP struct {
	mu      sync.Mutex
	stream  []byte
	closed  bool
	closes  int
	updated chan struct{}
	closeCh chan struct{}

	closeOnce sync.Once
}

func newWriterTestImmediateHTTP() *writerTestImmediateHTTP {
	return &writerTestImmediateHTTP{
		updated: make(chan struct{}, 1),
		closeCh: make(chan struct{}),
	}
}

func (w *writerTestImmediateHTTP) Read([]byte) (int, error) { return 0, io.EOF }

func (w *writerTestImmediateHTTP) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	w.stream = append(w.stream, p...)
	select {
	case w.updated <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (w *writerTestImmediateHTTP) close() error {
	w.mu.Lock()
	w.closes++
	w.closed = true
	w.mu.Unlock()
	w.closeOnce.Do(func() { close(w.closeCh) })
	return nil
}

func (w *writerTestImmediateHTTP) snapshot() ([]byte, int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.stream...), w.closes, w.closed
}

type writerTestBlockingHTTP struct {
	writeStarted chan struct{}
	writeDone    chan struct{}
	releaseWrite chan struct{}
	closeCh      chan struct{}
	updated      chan struct{}

	mu     sync.Mutex
	stream []byte
	closed bool
	closes int

	startOnce   sync.Once
	doneOnce    sync.Once
	releaseOnce sync.Once
	closeOnce   sync.Once
}

func newWriterTestBlockingHTTP() *writerTestBlockingHTTP {
	return &writerTestBlockingHTTP{
		writeStarted: make(chan struct{}),
		writeDone:    make(chan struct{}),
		releaseWrite: make(chan struct{}),
		closeCh:      make(chan struct{}),
		updated:      make(chan struct{}, 1),
	}
}

func (w *writerTestBlockingHTTP) Read([]byte) (int, error) { return 0, io.EOF }

func (w *writerTestBlockingHTTP) Write(p []byte) (int, error) {
	w.startOnce.Do(func() { close(w.writeStarted) })
	<-w.releaseWrite
	w.mu.Lock()
	defer w.mu.Unlock()
	defer w.doneOnce.Do(func() { close(w.writeDone) })
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	w.stream = append(w.stream, p...)
	select {
	case w.updated <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (w *writerTestBlockingHTTP) release() {
	w.releaseOnce.Do(func() { close(w.releaseWrite) })
}

func (w *writerTestBlockingHTTP) close() error {
	w.mu.Lock()
	w.closes++
	w.closed = true
	w.mu.Unlock()
	w.closeOnce.Do(func() { close(w.closeCh) })
	w.release()
	return nil
}

func (w *writerTestBlockingHTTP) snapshot() ([]byte, int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.stream...), w.closes, w.closed
}

type writerTestGateFailHTTP struct {
	started chan struct{}
	release chan struct{}
	err     error

	startOnce   sync.Once
	releaseOnce sync.Once
}

func newWriterTestGateFailHTTP(err error) *writerTestGateFailHTTP {
	return &writerTestGateFailHTTP{
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     err,
	}
}

func (w *writerTestGateFailHTTP) Read([]byte) (int, error) { return 0, io.EOF }

func (w *writerTestGateFailHTTP) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	return 0, w.err
}

func (w *writerTestGateFailHTTP) unblock() {
	w.releaseOnce.Do(func() { close(w.release) })
}

type writerTestOneByteHTTP struct {
	mu     sync.Mutex
	stream []byte
}

func (w *writerTestOneByteHTTP) Read([]byte) (int, error) { return 0, io.EOF }

func (w *writerTestOneByteHTTP) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	w.stream = append(w.stream, p[0])
	w.mu.Unlock()
	return 1, nil
}

func (w *writerTestOneByteHTTP) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.stream...)
}

type writerTestZeroWriter struct {
	calls atomic.Int32
}

func (w *writerTestZeroWriter) Write([]byte) (int, error) {
	w.calls.Add(1)
	return 0, nil
}

// This test protects the writer's load-bearing synchronization contract. It is
// intentionally run under the package race job: DATA handoff and both
// terminal transitions must remain panic-free and idempotent under overlap.
func TestHTTPConnectWriterConcurrentTerminalTransitions(t *testing.T) {
	const iterations = 300
	for i := 0; i < iterations; i++ {
		server := newWriterTestServer()
		var closeCalls atomic.Int32
		connection := &ProxyClientConnection{
			Mode:      ModeHTTPConnect,
			HTTP:      newWriterTestImmediateHTTP(),
			CloseHTTP: func() error { closeCalls.Add(1); return nil },
			closed:    make(chan struct{}),
			agentID:   "race-agent",
			connectID: int64(i + 1),
		}
		writer, attached := connection.attachHTTPWriter(server, nil, false)
		if !attached {
			t.Fatal("failed to attach writer to a live connection")
		}
		writer.start()

		start := make(chan struct{})
		var workers sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			workers.Add(1)
			go func(worker int) {
				defer workers.Done()
				<-start
				for packet := 0; packet < 8; packet++ {
					writer.handoffData([]byte{byte(worker), byte(packet)})
				}
			}(worker)
		}
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			writer.beginGracefulClose()
		}()
		go func() {
			defer workers.Done()
			<-start
			writer.abort(httpConnectAbortFrontendClose)
		}()

		close(start)
		workers.Wait()
		// Replay both transitions after the raced calls return to verify that the
		// terminal APIs remain idempotent.
		writer.abort(httpConnectAbortWriteFailure)
		writer.beginGracefulClose()

		writerTestEventually(t, "exactly one terminal HTTP close", func() bool {
			return closeCalls.Load() == 1
		})
		writer.mu.Lock()
		accepting, aborted, closeSeen := writer.accepting, writer.aborted, writer.closeResponseSeen
		writer.mu.Unlock()
		if accepting || !aborted || !closeSeen {
			t.Fatalf("terminal writer state = accepting:%t aborted:%t closeResponseSeen:%t", accepting, aborted, closeSeen)
		}
		if got := closeCalls.Load(); got != 1 {
			t.Fatalf("CloseHTTP calls = %d, want 1", got)
		}
	}
}

// A stale asynchronous graceful completion must not evict a replacement that
// reused the same protocol IDs.
func TestHTTPConnectStaleWriterCannotRemoveReplacement(t *testing.T) {
	const (
		agentID   = "reuse-agent"
		connectID = int64(73)
	)
	server := newWriterTestServer()
	oldHTTP := newWriterTestBlockingHTTP()
	oldConnection := &ProxyClientConnection{
		Mode:      ModeHTTPConnect,
		HTTP:      oldHTTP,
		CloseHTTP: oldHTTP.close,
		closed:    make(chan struct{}),
		agentID:   agentID,
		connectID: connectID,
	}
	server.addEstablished(agentID, connectID, oldConnection)
	oldWriter, _ := oldConnection.attachHTTPWriter(server, nil, false)
	oldWriter.start()
	if !oldWriter.handoffData([]byte("old payload")) {
		t.Fatal("old writer rejected DATA handoff")
	}
	select {
	case <-oldHTTP.writeStarted:
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("old writer did not enter its blocked write")
	}
	oldWriter.beginGracefulClose()

	replacement := &ProxyClientConnection{Mode: ModeHTTPConnect, agentID: agentID, connectID: connectID}
	server.addEstablished(agentID, connectID, replacement)
	oldHTTP.release()
	select {
	case <-oldHTTP.closeCh:
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("stale writer did not finish graceful cleanup")
	}

	got, err := server.getFrontend(agentID, connectID)
	if err != nil {
		t.Fatalf("replacement was removed by stale completion: %v", err)
	}
	if got != replacement {
		t.Fatalf("established pointer = %p, want replacement %p", got, replacement)
	}
}

func TestHTTPConnectWriterPreservesBytesAcrossPartialWrites(t *testing.T) {
	const (
		agentID   = "partial-agent"
		connectID = int64(91)
	)
	payloads := [][]byte{[]byte("alpha"), []byte("-"), []byte("beta"), []byte("-gamma")}
	want := bytes.Join(payloads, nil)
	server := newWriterTestServer()
	httpWriter := &writerTestOneByteHTTP{}
	connection := &ProxyClientConnection{
		Mode:      ModeHTTPConnect,
		HTTP:      httpWriter,
		closed:    make(chan struct{}),
		agentID:   agentID,
		connectID: connectID,
	}
	server.addEstablished(agentID, connectID, connection)
	writer, _ := connection.attachHTTPWriter(server, nil, false)
	writer.start()
	for _, payload := range payloads {
		if !writer.handoffData(payload) {
			t.Fatal("writer rejected DATA handoff")
		}
	}
	writer.beginGracefulClose()
	select {
	case <-connection.closed:
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("partial-write stream did not close after draining")
	}
	if got := httpWriter.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("reassembled stream = %q, want %q", got, want)
	}

	zeroWriter := &writerTestZeroWriter{}
	if err := writeAll(zeroWriter, []byte("no progress")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress write error = %v, want %v", err, io.ErrShortWrite)
	}
	if got := zeroWriter.calls.Load(); got != 1 {
		t.Fatalf("zero-progress writer calls = %d, want 1", got)
	}
}
