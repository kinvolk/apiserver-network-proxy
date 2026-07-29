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
	"sync"
	"testing"
)

func TestHTTPConnectResponseBufferPreservesBoundedByteStream(t *testing.T) {
	const capacity = int64(8)

	buffer := newHTTPConnectResponseBuffer(capacity)
	if !buffer.enqueue([]byte("abcdef")) {
		t.Fatal("response buffer rejected six bytes within its reserved eight-byte capacity")
	}
	if got := buffer.capacity(); got != capacity {
		t.Fatalf("response buffer capacity = %d, want %d", got, capacity)
	}
	if got := buffer.bufferedBytes(); got != 6 {
		t.Fatalf("response buffer occupancy after first enqueue = %d, want 6", got)
	}

	assertHTTPConnectResponseBufferHead(t, buffer, "abcdef")
	if buffer.consume(7) {
		t.Fatal("response buffer consumed beyond its buffered prefix")
	}
	if got := buffer.bufferedBytes(); got != 6 {
		t.Fatalf("response buffer occupancy after rejected over-consumption = %d, want 6", got)
	}
	assertHTTPConnectResponseBufferHead(t, buffer, "abcdef")
	if !buffer.consume(4) {
		t.Fatal("response buffer rejected consumption within its buffered prefix")
	}
	if !buffer.enqueue([]byte("ghijkl")) {
		t.Fatal("response buffer rejected bytes that exactly fill wrapped capacity")
	}
	if buffer.enqueue([]byte("x")) {
		t.Fatal("full response buffer accepted one byte beyond its reserved capacity")
	}
	if got := buffer.bufferedBytes(); got != capacity {
		t.Fatalf("response buffer occupancy after rejected overflow = %d, want %d", got, capacity)
	}

	assertHTTPConnectResponseBufferHead(t, buffer, "efgh")
	if !buffer.consume(3) {
		t.Fatal("response buffer rejected partial consumption before a wrap boundary")
	}
	assertHTTPConnectResponseBufferHead(t, buffer, "h")
	if !buffer.consume(1) {
		t.Fatal("response buffer rejected consumption at its wrap boundary")
	}
	assertHTTPConnectResponseBufferHead(t, buffer, "ijkl")
	if !buffer.consume(4) {
		t.Fatal("response buffer rejected final wrapped consumption")
	}
	if got := buffer.bufferedBytes(); got != 0 {
		t.Fatalf("drained response buffer occupancy = %d, want 0", got)
	}

	dataReady := requireEmptyHTTPConnectResponseBuffer(t, buffer)
	if !buffer.enqueue([]byte("12")) {
		t.Fatal("drained response buffer rejected reused capacity")
	}
	select {
	case <-dataReady:
	default:
		t.Fatal("response buffer did not publish reused data readiness")
	}
	assertHTTPConnectResponseBufferHead(t, buffer, "12")
}

func TestHTTPConnectResponseBufferReusesStorageForOneByteFrames(t *testing.T) {
	buffer := newHTTPConnectResponseBuffer(1)
	operationOK := true
	allocations := testing.AllocsPerRun(100, func() {
		if !buffer.enqueue([]byte{1}) {
			operationOK = false
			return
		}
		data, wait, open := buffer.peek()
		if !open || wait != nil || len(data) != 1 || data[0] != 1 {
			operationOK = false
			return
		}
		if !buffer.consume(1) {
			operationOK = false
		}
	})
	if !operationOK {
		t.Fatal("response buffer did not preserve one-byte enqueue and consume cycles")
	}
	if allocations != 0 {
		t.Fatalf("response buffer one-byte cycles allocated %.0f objects, want 0 queue-node growth", allocations)
	}
}

func TestHTTPConnectResponseBufferLinearizesProducerAndConsumer(t *testing.T) {
	const halfWindow = 32

	buffer := newHTTPConnectResponseBuffer(2 * halfWindow)
	if !buffer.enqueue(bytes.Repeat([]byte{0}, halfWindow)) {
		t.Fatal("concurrent response buffer fixture rejected its initial half-window")
	}

	for generation := byte(1); generation <= 64; generation++ {
		next := bytes.Repeat([]byte{generation}, halfWindow)
		start := make(chan struct{})
		results := make(chan bool, 2)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			results <- buffer.enqueue(next)
		}()
		go func() {
			defer workers.Done()
			<-start
			results <- buffer.consume(halfWindow)
		}()
		close(start)
		workers.Wait()
		close(results)
		for ok := range results {
			if !ok {
				t.Fatalf("response buffer rejected a valid producer/consumer transition at generation %d", generation)
			}
		}

		if got := buffer.bufferedBytes(); got != halfWindow {
			t.Fatalf("response buffer occupancy at generation %d = %d, want %d", generation, got, halfWindow)
		}
		data, wait, open := buffer.peek()
		if !open || wait != nil || !bytes.Equal(data, next) {
			t.Fatalf("response buffer head at generation %d = (%x, %p, %v), want (%x, nil, true)", generation, data, wait, open, next)
		}
	}
}

func TestHTTPConnectResponseBufferLinearizesEnqueueWithClose(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		buffer := newHTTPConnectResponseBuffer(1)
		start := make(chan struct{})
		enqueued := make(chan bool, 1)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			enqueued <- buffer.enqueue([]byte{1})
		}()
		go func() {
			defer workers.Done()
			<-start
			buffer.close()
		}()
		close(start)
		workers.Wait()

		if <-enqueued {
			data, wait, open := buffer.peek()
			if !open || wait != nil || !bytes.Equal(data, []byte{1}) {
				t.Fatalf("enqueue-winning close race %d peek = (%x, %p, %v), want (01, nil, true)", iteration, data, wait, open)
			}
			if !buffer.consume(1) {
				t.Fatalf("enqueue-winning close race %d rejected its accepted byte", iteration)
			}
		}

		if data, wait, open := buffer.peek(); len(data) != 0 || wait != nil || open {
			t.Fatalf("converged enqueue/close race %d peek = (%x, %p, %v), want (empty, nil, false)", iteration, data, wait, open)
		}
		if buffer.enqueue([]byte{2}) {
			t.Fatalf("converged enqueue/close race %d accepted a post-close byte", iteration)
		}
	}
}

func TestHTTPConnectResponseBufferCloseWakesAndDrains(t *testing.T) {
	buffer := newHTTPConnectResponseBuffer(4)
	dataReady := requireEmptyHTTPConnectResponseBuffer(t, buffer)

	buffer.close()
	select {
	case <-dataReady:
	default:
		t.Fatal("closing an empty response buffer did not wake its waiter")
	}
	if buffer.enqueue([]byte("x")) {
		t.Fatal("closed response buffer accepted new bytes")
	}
	if data, wait, open := buffer.peek(); len(data) != 0 || wait != nil || open {
		t.Fatalf("closed empty response buffer peek = (%q, %p, %v), want (empty, nil, false)", data, wait, open)
	}
	buffer.close()

	draining := newHTTPConnectResponseBuffer(4)
	if !draining.enqueue([]byte("abc")) {
		t.Fatal("response buffer rejected bytes before close")
	}
	draining.close()
	assertHTTPConnectResponseBufferHead(t, draining, "abc")
	if !draining.consume(3) {
		t.Fatal("closed response buffer rejected already-buffered consumption")
	}
	if data, wait, open := draining.peek(); len(data) != 0 || wait != nil || open {
		t.Fatalf("drained closed response buffer peek = (%q, %p, %v), want (empty, nil, false)", data, wait, open)
	}
}

func assertHTTPConnectResponseBufferHead(t *testing.T, buffer *httpConnectResponseBuffer, want string) {
	t.Helper()
	data, wait, open := buffer.peek()
	if !open {
		t.Fatalf("response buffer closed with head %q still expected", want)
	}
	if wait != nil {
		t.Fatalf("response buffer returned wait channel %p with head %q expected", wait, want)
	}
	if !bytes.Equal(data, []byte(want)) {
		t.Fatalf("response buffer head = %q, want %q", data, want)
	}
}

func requireEmptyHTTPConnectResponseBuffer(t *testing.T, buffer *httpConnectResponseBuffer) <-chan struct{} {
	t.Helper()
	data, wait, open := buffer.peek()
	if !open {
		t.Fatal("empty response buffer closed before terminal transition")
	}
	if len(data) != 0 || wait == nil {
		t.Fatalf("empty response buffer peek = (%q, %p), want (empty, non-nil wait)", data, wait)
	}
	return wait
}
