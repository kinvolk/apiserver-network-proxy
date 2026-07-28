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

// httpConnectResponseFlowControlAdmissionState is the connection-owned slot
// between allocator admission and later response-flow setup.
// ProxyClientConnection.httpMu protects every field. reservationReady reports
// only provisional resource ownership: the allocator's reservation value is
// consumed exclusively by this slot. Before production wiring treats that
// signal as admission success, it must revalidate the backend generation,
// endpoint, and selected response mode in addition to the terminal-state check
// performed here.
type httpConnectResponseFlowControlAdmissionState struct {
	admission        *httpConnectFlowControlAdmission
	reservation      *httpConnectFlowControlReservation
	reservationReady chan struct{}
	stopReceiver     chan struct{}
	done             chan struct{}
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

// startHTTPConnectResponseFlowControlAdmission transfers one allocator
// admission to the connection. The caller invokes it once after claiming the
// PendingDial entry. No caller receives from admission.reservationReady after
// this ownership transfer. If started is false, no ownership transfer occurred
// and the caller remains responsible for the supplied admission.
func (c *ProxyClientConnection) startHTTPConnectResponseFlowControlAdmission(
	admission *httpConnectFlowControlAdmission,
) (reservationReady, done <-chan struct{}, started bool) {
	reservationSource := admission.reservationReady()
	state := &httpConnectResponseFlowControlAdmissionState{
		admission:        admission,
		reservationReady: make(chan struct{}),
		stopReceiver:     make(chan struct{}),
		done:             make(chan struct{}),
	}

	var (
		reservationToRelease *httpConnectFlowControlReservation
		stopReceiver         chan struct{}
		flowControlDone      chan struct{}
		receiveReservation   bool
	)
	c.httpMu.Lock()
	if c.httpResponseFlowControlStarted {
		c.httpMu.Unlock()
		return nil, nil, false
	}
	c.httpResponseFlowControlStarted = true
	c.httpResponseFlowControlAdmission = state
	select {
	case reservation := <-reservationSource:
		state.admission = nil
		if c.httpTerminal {
			c.httpResponseFlowControlAdmission = nil
			reservationToRelease = reservation
			flowControlDone = state.done
		} else {
			state.reservation = reservation
			// Publish provisional ownership only. Establishment still owes the
			// revalidation documented on httpConnectResponseFlowControlAdmissionState.
			close(state.reservationReady)
		}
	default:
		receiveReservation = true
		if c.httpTerminal && admission.cancel() {
			c.httpResponseFlowControlAdmission = nil
			state.admission = nil
			stopReceiver = state.stopReceiver
			flowControlDone = state.done
			receiveReservation = false
		}
	}
	c.httpMu.Unlock()

	finishHTTPConnectResponseFlowControlTermination(reservationToRelease, stopReceiver, flowControlDone)
	if receiveReservation {
		go c.receiveHTTPConnectResponseFlowControlReservation(state, reservationSource)
	}
	return state.reservationReady, state.done, true
}

// receiveHTTPConnectResponseFlowControlReservation is the sole receiver for a
// queued admission. If terminal state won after allocator assignment, it
// drains and releases the reachable reservation instead of publishing it.
func (c *ProxyClientConnection) receiveHTTPConnectResponseFlowControlReservation(
	state *httpConnectResponseFlowControlAdmissionState,
	reservationSource <-chan *httpConnectFlowControlReservation,
) {
	select {
	case reservation := <-reservationSource:
		c.httpMu.Lock()
		if c.httpResponseFlowControlAdmission != state {
			c.httpMu.Unlock()
			reservation.release()
			return
		}
		state.admission = nil
		if c.httpTerminal {
			c.httpResponseFlowControlAdmission = nil
			c.httpMu.Unlock()
			reservation.release()
			close(state.done)
			return
		}
		state.reservation = reservation
		// Publish provisional ownership only. Establishment still owes the
		// revalidation documented on httpConnectResponseFlowControlAdmissionState.
		close(state.reservationReady)
		c.httpMu.Unlock()
	case <-state.stopReceiver:
	}
}

// takeHTTPConnectResponseFlowControlTerminationLocked transfers terminal
// cleanup ownership to the caller. A false admission cancellation means
// allocator assignment won; the sole receiver remains responsible for
// draining and releasing that reservation after observing httpTerminal.
func (c *ProxyClientConnection) takeHTTPConnectResponseFlowControlTerminationLocked() (
	reservation *httpConnectFlowControlReservation,
	stopReceiver, done chan struct{},
) {
	state := c.httpResponseFlowControlAdmission
	if state == nil {
		return nil, nil, nil
	}
	if state.reservation != nil {
		c.httpResponseFlowControlAdmission = nil
		reservation = state.reservation
		state.reservation = nil
		return reservation, nil, state.done
	}
	if state.admission != nil && state.admission.cancel() {
		c.httpResponseFlowControlAdmission = nil
		state.admission = nil
		return nil, state.stopReceiver, state.done
	}
	return nil, nil, nil
}

func finishHTTPConnectResponseFlowControlTermination(
	reservation *httpConnectFlowControlReservation,
	stopReceiver, done chan struct{},
) {
	if stopReceiver != nil {
		close(stopReceiver)
	}
	if reservation != nil {
		reservation.release()
	}
	if done != nil {
		close(done)
	}
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
