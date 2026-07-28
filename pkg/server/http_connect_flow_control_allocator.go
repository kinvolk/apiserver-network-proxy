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

type httpConnectFlowControlAdmissionStatus string

const (
	httpConnectFlowControlAdmissionGranted       httpConnectFlowControlAdmissionStatus = "granted"
	httpConnectFlowControlAdmissionQueued        httpConnectFlowControlAdmissionStatus = "queued"
	httpConnectFlowControlAdmissionQueueDisabled httpConnectFlowControlAdmissionStatus = "queue_disabled"
	httpConnectFlowControlAdmissionQueueFull     httpConnectFlowControlAdmissionStatus = "queue_full"
)

type httpConnectFlowControlAllocator struct {
	mu sync.Mutex

	windowSize           int64
	maxReservations      int64
	reservedReservations int64
	maxPendingAdmissions int
	pendingAdmissions    []*httpConnectFlowControlAdmission
}

type httpConnectFlowControlAdmission struct {
	allocator *httpConnectFlowControlAllocator
	ready     chan *httpConnectFlowControlReservation
	pending   bool
}

type httpConnectFlowControlReservation struct {
	allocator   *httpConnectFlowControlAllocator
	releaseOnce sync.Once
}

func newHTTPConnectFlowControlAllocator(windowSize, poolSize int64, maxPendingAdmissions int) *httpConnectFlowControlAllocator {
	return &httpConnectFlowControlAllocator{
		windowSize:           windowSize,
		maxReservations:      poolSize / windowSize,
		maxPendingAdmissions: maxPendingAdmissions,
	}
}

func (a *httpConnectFlowControlAllocator) admit() (*httpConnectFlowControlAdmission, httpConnectFlowControlAdmissionStatus) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.reservedReservations < a.maxReservations {
		a.reservedReservations++
		admission := a.newAdmission(false)
		admission.ready <- a.newReservation()
		return admission, httpConnectFlowControlAdmissionGranted
	}
	if a.maxPendingAdmissions == 0 {
		return nil, httpConnectFlowControlAdmissionQueueDisabled
	}
	if len(a.pendingAdmissions) >= a.maxPendingAdmissions {
		return nil, httpConnectFlowControlAdmissionQueueFull
	}

	admission := a.newAdmission(true)
	a.pendingAdmissions = append(a.pendingAdmissions, admission)
	return admission, httpConnectFlowControlAdmissionQueued
}

func (a *httpConnectFlowControlAdmission) reservationReady() <-chan *httpConnectFlowControlReservation {
	return a.ready
}

// startHTTPConnectResponseFlowControlAdmission is an inert seam for the
// connection-owned admission lifecycle contract.
func (c *ProxyClientConnection) startHTTPConnectResponseFlowControlAdmission(
	admission *httpConnectFlowControlAdmission,
) (reservationReady, done <-chan struct{}) {
	return make(chan struct{}), make(chan struct{})
}

func (a *httpConnectFlowControlAdmission) cancel() bool {
	a.allocator.mu.Lock()
	defer a.allocator.mu.Unlock()

	if !a.pending {
		return false
	}
	for i, pending := range a.allocator.pendingAdmissions {
		if pending != a {
			continue
		}
		copy(a.allocator.pendingAdmissions[i:], a.allocator.pendingAdmissions[i+1:])
		last := len(a.allocator.pendingAdmissions) - 1
		a.allocator.pendingAdmissions[last] = nil
		a.allocator.pendingAdmissions = a.allocator.pendingAdmissions[:last]
		a.pending = false
		return true
	}
	return false
}

func (r *httpConnectFlowControlReservation) release() {
	r.releaseOnce.Do(r.allocator.release)
}

func (a *httpConnectFlowControlAllocator) usage() (reservedBytes int64, pendingAdmissions int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reservedReservations * a.windowSize, len(a.pendingAdmissions)
}

func (a *httpConnectFlowControlAllocator) newAdmission(pending bool) *httpConnectFlowControlAdmission {
	return &httpConnectFlowControlAdmission{
		allocator: a,
		ready:     make(chan *httpConnectFlowControlReservation, 1),
		pending:   pending,
	}
}

func (a *httpConnectFlowControlAllocator) newReservation() *httpConnectFlowControlReservation {
	return &httpConnectFlowControlReservation{allocator: a}
}

func (a *httpConnectFlowControlAllocator) release() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pendingAdmissions) == 0 {
		a.reservedReservations--
		return
	}

	next := a.pendingAdmissions[0]
	copy(a.pendingAdmissions, a.pendingAdmissions[1:])
	last := len(a.pendingAdmissions) - 1
	a.pendingAdmissions[last] = nil
	a.pendingAdmissions = a.pendingAdmissions[:last]
	next.pending = false
	next.ready <- a.newReservation()
}
