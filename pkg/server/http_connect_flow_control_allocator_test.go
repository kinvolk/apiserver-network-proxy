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
	"testing"
	"time"

	"sigs.k8s.io/apiserver-network-proxy/pkg/server/proxystrategies"
)

func TestHTTPConnectFlowControlAllocatorReservesExactConfiguredCapacity(t *testing.T) {
	const (
		windowSize = int64(64 << 10)
		poolSize   = int64(100 << 10)
	)
	allocator := newHTTPConnectFlowControlAllocator(windowSize, poolSize, 0)

	admission := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted)
	reservation := requireHTTPConnectFlowControlReservation(t, admission)
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, 0)

	rejected, status := allocator.admit()
	if status != httpConnectFlowControlAdmissionQueueDisabled {
		t.Fatalf("admission beyond floor(pool/window) status = %q, want %q", status, httpConnectFlowControlAdmissionQueueDisabled)
	}
	if rejected != nil {
		t.Fatal("queue-disabled admission returned state")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, 0)

	reservation.release()
	reservation.release()
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestHTTPConnectFlowControlAllocatorBoundsPendingAdmissions(t *testing.T) {
	const windowSize = int64(32)
	allocator := newHTTPConnectFlowControlAllocator(windowSize, windowSize, 2)

	holder := requireHTTPConnectFlowControlReservation(
		t,
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted),
	)
	first := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)
	second := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)
	requireNoHTTPConnectFlowControlReservation(t, first)
	requireNoHTTPConnectFlowControlReservation(t, second)

	rejected, status := allocator.admit()
	if status != httpConnectFlowControlAdmissionQueueFull {
		t.Fatalf("admission beyond pending limit status = %q, want %q", status, httpConnectFlowControlAdmissionQueueFull)
	}
	if rejected != nil {
		t.Fatal("queue-full admission returned state")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, 2)

	if !first.cancel() {
		t.Fatal("first pending admission cancellation lost without a competing grant")
	}
	if !second.cancel() {
		t.Fatal("second pending admission cancellation lost without a competing grant")
	}
	holder.release()
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestHTTPConnectFlowControlAllocatorAdmitsPendingInFIFOOrder(t *testing.T) {
	const windowSize = int64(16)
	allocator := newHTTPConnectFlowControlAllocator(windowSize, windowSize, 3)

	holder := requireHTTPConnectFlowControlReservation(
		t,
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted),
	)
	admissions := []*httpConnectFlowControlAdmission{
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued),
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued),
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued),
	}

	holder.release()
	for i, admission := range admissions {
		reservation := requireHTTPConnectFlowControlReservation(t, admission)
		for _, later := range admissions[i+1:] {
			requireNoHTTPConnectFlowControlReservation(t, later)
		}
		assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, len(admissions)-i-1)
		reservation.release()
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestHTTPConnectFlowControlAllocatorSkipsCancelledAdmission(t *testing.T) {
	const windowSize = int64(8)
	allocator := newHTTPConnectFlowControlAllocator(windowSize, windowSize, 2)

	holder := requireHTTPConnectFlowControlReservation(
		t,
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted),
	)
	cancelled := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)
	next := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)

	if !cancelled.cancel() {
		t.Fatal("pending admission cancellation lost without a competing grant")
	}
	if cancelled.cancel() {
		t.Fatal("pending admission cancellation succeeded more than once")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, 1)

	holder.release()
	requireNoHTTPConnectFlowControlReservation(t, cancelled)
	reservation := requireHTTPConnectFlowControlReservation(t, next)
	if next.cancel() {
		t.Fatal("cancellation won after capacity assignment")
	}
	reservation.release()
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestHTTPConnectFlowControlAllocatorLinearizesCancellationWithAssignment(t *testing.T) {
	const windowSize = int64(8)
	allocator := newHTTPConnectFlowControlAllocator(windowSize, windowSize, 1)

	holder := requireHTTPConnectFlowControlReservation(
		t,
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted),
	)
	waiter := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)

	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	releaseDone := make(chan struct{})
	cancelResult := make(chan bool, 1)
	go func() {
		ready <- struct{}{}
		<-start
		holder.release()
		close(releaseDone)
	}()
	go func() {
		ready <- struct{}{}
		<-start
		cancelResult <- waiter.cancel()
	}()

	// Make both transitions eligible together. Either may win, but the result
	// must agree with reservation ownership after both operations complete.
	<-ready
	<-ready
	close(start)
	cancellationWon := <-cancelResult
	<-releaseDone

	if cancellationWon {
		requireNoHTTPConnectFlowControlReservation(t, waiter)
	} else {
		reservation := requireHTTPConnectFlowControlReservation(t, waiter)
		reservation.release()
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestProxyServerHTTPConnectFlowControlAllocatorUsesConfiguredLimits(t *testing.T) {
	const (
		windowSize           = int64(17)
		poolSize             = int64(101)
		maxPendingAdmissions = 2
	)
	server := NewProxyServer("", []proxystrategies.ProxyStrategy{proxystrategies.ProxyStrategyDefault}, 1, nil, 10)
	if server.httpConnectFlowControlAllocator == nil {
		t.Fatal("NewProxyServer HTTP CONNECT flow-control allocator = nil")
	}
	server.SetHTTPConnectFlowControlConfig(windowSize, poolSize, maxPendingAdmissions, time.Second)
	allocator := server.httpConnectFlowControlAllocator

	reservations := make([]*httpConnectFlowControlReservation, 0, poolSize/windowSize)
	for range poolSize / windowSize {
		admission := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted)
		reservations = append(reservations, requireHTTPConnectFlowControlReservation(t, admission))
	}
	first := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)
	second := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionQueued)
	rejected, status := allocator.admit()
	if status != httpConnectFlowControlAdmissionQueueFull {
		t.Fatalf("configured pending limit overflow status = %q, want %q", status, httpConnectFlowControlAdmissionQueueFull)
	}
	if rejected != nil {
		t.Fatal("configured pending limit overflow returned admission state")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, (poolSize/windowSize)*windowSize, maxPendingAdmissions)

	if !first.cancel() || !second.cancel() {
		t.Fatal("configured pending admissions did not cancel")
	}
	for _, reservation := range reservations {
		reservation.release()
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func requireHTTPConnectFlowControlAdmission(
	t *testing.T,
	allocator *httpConnectFlowControlAllocator,
	wantStatus httpConnectFlowControlAdmissionStatus,
) *httpConnectFlowControlAdmission {
	t.Helper()
	admission, status := allocator.admit()
	if status != wantStatus {
		t.Fatalf("admission status = %q, want %q", status, wantStatus)
	}
	if admission == nil {
		t.Fatalf("admission state = nil for status %q", status)
	}
	return admission
}

func requireHTTPConnectFlowControlReservation(
	t *testing.T,
	admission *httpConnectFlowControlAdmission,
) *httpConnectFlowControlReservation {
	t.Helper()
	select {
	case reservation := <-admission.reservationReady():
		if reservation == nil {
			t.Fatal("admission published a nil reservation")
		}
		return reservation
	default:
		t.Fatal("admission did not synchronously publish its reservation")
		return nil
	}
}

func requireNoHTTPConnectFlowControlReservation(t *testing.T, admission *httpConnectFlowControlAdmission) {
	t.Helper()
	select {
	case reservation := <-admission.reservationReady():
		t.Fatalf("pending admission unexpectedly published reservation %p", reservation)
	default:
	}
}

func assertHTTPConnectFlowControlAllocatorUsage(
	t *testing.T,
	allocator *httpConnectFlowControlAllocator,
	wantReservedBytes int64,
	wantPendingAdmissions int,
) {
	t.Helper()
	reservedBytes, pendingAdmissions := allocator.usage()
	if reservedBytes != wantReservedBytes {
		t.Errorf("reserved bytes = %d, want %d", reservedBytes, wantReservedBytes)
	}
	if pendingAdmissions != wantPendingAdmissions {
		t.Errorf("pending admissions = %d, want %d", pendingAdmissions, wantPendingAdmissions)
	}
}
