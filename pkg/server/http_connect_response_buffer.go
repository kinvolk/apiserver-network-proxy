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

import "sync"

// httpConnectResponseBuffer is a fixed-capacity byte ring. One backend
// receiver enqueues DATA and one connection-owned HTTP writer peeks and
// consumes it. Packet boundaries are deliberately not retained.
type httpConnectResponseBuffer struct {
	mu sync.Mutex

	storage    []byte
	readOffset int64
	buffered   int64
	dataReady  chan struct{}
	closed     bool
}

func newHTTPConnectResponseBuffer(capacity int64) *httpConnectResponseBuffer {
	return &httpConnectResponseBuffer{
		storage:   make([]byte, capacity),
		dataReady: make(chan struct{}, 1),
	}
}

// enqueue copies data into already-reserved capacity without waiting for
// ordinary buffer space. False means the buffer is closed or data would exceed
// that capacity; neither outcome mutates the byte stream.
func (b *httpConnectResponseBuffer) enqueue(data []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	dataLength := int64(len(data))
	capacity := int64(len(b.storage))
	if b.closed || dataLength > capacity-b.buffered {
		return false
	}
	if dataLength == 0 {
		return true
	}

	writeOffset := (b.readOffset + b.buffered) % capacity
	firstLength := min(dataLength, capacity-writeOffset)
	copy(b.storage[writeOffset:writeOffset+firstLength], data[:firstLength])
	copy(b.storage[:dataLength-firstLength], data[firstLength:])
	wasEmpty := b.buffered == 0
	b.buffered += dataLength
	if wasEmpty {
		select {
		case b.dataReady <- struct{}{}:
		default:
		}
	}
	return true
}

// peek returns the next contiguous byte span without removing it. The sole
// consumer may use the returned slice without holding mu until its next
// consume call: enqueue writes only into the disjoint free region. An empty,
// open buffer returns its reusable readiness channel; a drained, closed buffer
// returns open false.
func (b *httpConnectResponseBuffer) peek() (data []byte, wait <-chan struct{}, open bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buffered > 0 {
		length := min(b.buffered, int64(len(b.storage))-b.readOffset)
		return b.storage[b.readOffset : b.readOffset+length : b.readOffset+length], nil, true
	}
	if b.closed {
		return nil, nil, false
	}
	return nil, b.dataReady, true
}

// consume removes a successfully written prefix. False leaves the buffer
// unchanged when the requested prefix is negative or exceeds current data.
func (b *httpConnectResponseBuffer) consume(length int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	consumed := int64(length)
	if consumed < 0 || consumed > b.buffered {
		return false
	}
	if consumed == 0 {
		return true
	}

	b.readOffset = (b.readOffset + consumed) % int64(len(b.storage))
	b.buffered -= consumed
	if b.buffered == 0 {
		b.readOffset = 0
		select {
		case <-b.dataReady:
		default:
		}
	}
	return true
}

func (b *httpConnectResponseBuffer) capacity() int64 {
	return int64(len(b.storage))
}

func (b *httpConnectResponseBuffer) bufferedBytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffered
}

// close rejects new bytes and wakes an empty waiter. Bytes already accepted
// remain available to the sole consumer before peek reports the closed state.
func (b *httpConnectResponseBuffer) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	close(b.dataReady)
}
