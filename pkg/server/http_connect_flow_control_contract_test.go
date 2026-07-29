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
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server/proxystrategies"
)

func TestHTTPConnectDialOffersResponseFlowControlV1WhenEnabled(t *testing.T) {
	dialRequest, pending := httpConnectFlowControlDialRequest(t, true)
	sentOffer := slices.Clone(dialRequest.GetOfferedFlowControlFeatures())
	want := []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
	if got := sentOffer; !slices.Equal(got, want) {
		t.Fatalf("DIAL_REQ offered flow-control features = %v, want %v", got, want)
	}

	dialRequest.OfferedFlowControlFeatures[0] = client.FlowControlFeature_FLOW_CONTROL_FEATURE_UNSPECIFIED
	if got := pending.offeredFlowControlFeatures; !slices.Equal(got, sentOffer) {
		t.Fatalf("pending dial recorded flow-control features = %v, want defensive copy of sent offer %v", got, sentOffer)
	}
}

func TestHTTPConnectDialDoesNotOfferFlowControlWhenDisabled(t *testing.T) {
	dialRequest, _ := httpConnectFlowControlDialRequest(t, false)
	if got := dialRequest.GetOfferedFlowControlFeatures(); len(got) != 0 {
		t.Fatalf("DIAL_REQ offered flow-control features = %v, want no offer", got)
	}
}

func TestHTTPConnectAcceptedResponseFlowControlEstablishesAtZeroCredit(t *testing.T) {
	const (
		connectID  = int64(6201)
		windowSize = int64(32)
	)

	fixture := newHTTPConnectFlowControlDialFixtureWithBlockedHTTPWrite(t, true)
	fixture.proxyServer.SetHTTPConnectFlowControlConfig(windowSize, windowSize, 1, time.Second)
	allocator := fixture.proxyServer.httpConnectFlowControlAllocator
	holder := requireHTTPConnectFlowControlReservation(
		t,
		requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted),
	)
	t.Cleanup(holder.release)

	want := []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
	offered := slices.Clone(fixture.dialRequest.GetOfferedFlowControlFeatures())
	if !slices.Equal(offered, want) {
		t.Fatalf("DIAL_REQ offered flow-control features = %v, want %v", offered, want)
	}

	consumer := startWriterTestBackendConsumer(t, fixture.proxyServer, fixture.backend, fixture.agentID, 1)
	consumer.recvCh <- &client.Packet{
		Type: client.PacketType_DIAL_RSP,
		Payload: &client.Packet_DialResponse{
			DialResponse: &client.DialResponse{
				Random:                      fixture.dialRequest.GetRandom(),
				ConnectID:                   connectID,
				AcceptedFlowControlFeatures: offered,
			},
		},
	}

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(writerTestSafetyTimeout)
	defer timer.Stop()
	for {
		reservedBytes, pendingAdmissions := allocator.usage()
		if reservedBytes == windowSize && pendingAdmissions == 1 {
			break
		}
		select {
		case <-fixture.pending.connected:
			t.Fatal("response V1 signaled connected before flow-control admission ownership")
		case <-fixture.frontendConn.sink.firstWriteStarted:
			t.Fatal("response V1 started HTTP 200 before flow-control admission ownership")
		case <-fixture.frontendConn.sink.closeObserved:
			t.Fatal("response V1 closed the frontend instead of joining flow-control admission")
		case <-ticker.C:
		case <-timer.C:
			t.Fatalf("response V1 allocator usage = (%d, %d), want (%d, 1)", reservedBytes, pendingAdmissions, windowSize)
		}
	}

	fixture.pending.httpMu.Lock()
	state := fixture.pending.httpResponseFlowControlAdmission
	writer := fixture.pending.httpWriter
	started := fixture.pending.httpResponseFlowControlStarted
	selectedMode := fixture.pending.httpConnectResponseMode
	fixture.pending.httpMu.Unlock()
	if !started || state == nil {
		t.Fatalf("response V1 admission ownership = (%v, %p), want (true, non-nil)", started, state)
	}
	if writer != nil {
		t.Fatalf("queued response V1 attached HTTP writer %p before admission", writer)
	}
	if selectedMode != httpConnectResponseModeAgentToServerByteWindowV1 {
		t.Fatalf("queued connection response mode = %q, want %q", selectedMode, httpConnectResponseModeAgentToServerByteWindowV1)
	}
	select {
	case <-fixture.pending.connected:
		t.Fatal("queued response V1 signaled connected")
	default:
	}
	written, _, _, _ := fixture.frontendConn.sink.snapshot()
	if len(written) != 0 {
		t.Fatalf("queued response V1 wrote HTTP response %q, want none", written)
	}
	if _, err := fixture.proxyServer.getFrontend(fixture.agentID, connectID); err == nil {
		t.Fatal("queued response V1 published an established connection")
	}

	holder.release()
	select {
	case <-fixture.frontendConn.sink.firstWriteStarted:
	case <-state.done:
		t.Fatal("assigned response V1 became terminal before starting HTTP 200")
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("assigned response V1 did not start HTTP 200 after receiving capacity")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, windowSize, 0)
	fixture.pending.httpMu.Lock()
	installedState := fixture.pending.httpResponseFlowControl
	admissionState := fixture.pending.httpResponseFlowControlAdmission
	writer = fixture.pending.httpWriter
	terminal := fixture.pending.httpTerminal
	fixture.pending.httpMu.Unlock()
	if admissionState != nil {
		t.Fatal("assigned response V1 retained admission state after response-state installation")
	}
	if installedState == nil || installedState.reservation == nil {
		t.Fatal("assigned response V1 did not install connection-owned response state and reservation")
	}
	if installedState.done != state.done {
		t.Fatal("installed response V1 state did not retain admission lifecycle ownership")
	}
	if installedState.windowSize != windowSize {
		t.Fatalf("installed response V1 window size = %d, want %d", installedState.windowSize, windowSize)
	}
	if installedState.grantLimit != 0 || installedState.receivedTotal != 0 || installedState.consumedTotal != 0 {
		t.Fatalf("installed response V1 counters = (%d, %d, %d), want zero credit and progress", installedState.grantLimit, installedState.receivedTotal, installedState.consumedTotal)
	}
	if writer == nil {
		t.Fatal("installed response V1 state did not attach the sole HTTP writer")
	}
	if terminal {
		t.Fatal("installed response V1 state became terminal before HTTP 200 completed")
	}
	if got, err := fixture.proxyServer.getFrontend(fixture.agentID, connectID); err != nil || got != fixture.pending {
		t.Fatalf("published zero-credit connection = %p, %v; want %p", got, err, fixture.pending)
	}
	select {
	case <-fixture.pending.connected:
		t.Fatal("blocked HTTP 200 signaled connected before the complete response")
	default:
	}
	written, _, _, _ = fixture.frontendConn.sink.snapshot()
	if len(written) != 0 {
		t.Fatalf("blocked HTTP 200 exposed partial frontend bytes %q", written)
	}

	fixture.frontendConn.sink.release()
	select {
	case <-fixture.pending.connected:
	case <-state.done:
		t.Fatal("assigned response V1 became terminal before completing HTTP 200")
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("assigned response V1 did not signal connected after complete HTTP 200")
	}
	written, _, _, _ = fixture.frontendConn.sink.snapshot()
	if !bytes.Equal(written, []byte(httpConnectSuccessResponse)) {
		t.Fatalf("assigned response V1 wrote %q, want complete successful CONNECT response", written)
	}

	fixture.pending.abortHTTP(fixture.proxyServer, httpConnectAbortFrontendClose)
	select {
	case <-state.done:
	default:
		t.Fatal("terminal abort did not synchronously release production admission ownership")
	}
	assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
}

func TestHTTPConnectResponseFlowControlRevalidatesAssignedConnection(t *testing.T) {
	const (
		agentID    = "response-flow-revalidation-agent"
		connectID  = int64(6251)
		windowSize = int64(32)
	)

	tests := []struct {
		name   string
		mutate func(*ProxyClientConnection, context.CancelFunc, *Backend)
	}{
		{
			name: "frontend terminal state",
			mutate: func(connection *ProxyClientConnection, _ context.CancelFunc, _ *Backend) {
				connection.httpMu.Lock()
				connection.httpTerminal = true
				connection.httpMu.Unlock()
			},
		},
		{
			name: "backend generation",
			mutate: func(connection *ProxyClientConnection, _ context.CancelFunc, replacement *Backend) {
				connection.httpMu.Lock()
				connection.backend = replacement
				connection.httpMu.Unlock()
			},
		},
		{
			name: "backend context",
			mutate: func(_ *ProxyClientConnection, cancelBackend context.CancelFunc, _ *Backend) {
				cancelBackend()
			},
		},
		{
			name: "endpoint connect ID",
			mutate: func(connection *ProxyClientConnection, _ context.CancelFunc, _ *Backend) {
				connection.httpMu.Lock()
				connection.connectID++
				connection.httpMu.Unlock()
			},
		},
		{
			name: "endpoint agent ID",
			mutate: func(connection *ProxyClientConnection, _ context.CancelFunc, _ *Backend) {
				connection.httpMu.Lock()
				connection.agentID += "-replacement"
				connection.httpMu.Unlock()
			},
		},
		{
			name: "selected mode",
			mutate: func(connection *ProxyClientConnection, _ context.CancelFunc, _ *Backend) {
				connection.httpMu.Lock()
				connection.httpConnectResponseMode = httpConnectResponseModeLegacy
				connection.httpMu.Unlock()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendContext, cancelBackend := context.WithCancel(context.Background())
			defer cancelBackend()
			backend, _ := newWriterTestBackend(backendContext, agentID)
			replacementBackend, _ := newWriterTestBackend(context.Background(), agentID)
			server := newWriterTestServer()
			frontend := newWriterTestImmediateHTTP()
			connection := &ProxyClientConnection{
				Mode:                    ModeHTTPConnect,
				HTTP:                    frontend,
				CloseHTTP:               frontend.close,
				closed:                  make(chan struct{}),
				connected:               make(chan struct{}),
				backend:                 backend,
				agentID:                 agentID,
				connectID:               connectID,
				httpConnectResponseMode: httpConnectResponseModeAgentToServerByteWindowV1,
				httpInitialResponse:     []byte(httpConnectSuccessResponse),
			}
			allocator := newHTTPConnectFlowControlAllocator(windowSize, windowSize, 0)
			admission := requireHTTPConnectFlowControlAdmission(t, allocator, httpConnectFlowControlAdmissionGranted)
			reservationReady, done, started := connection.startHTTPConnectResponseFlowControlAdmission(admission)
			if !started {
				t.Fatal("revalidation fixture did not start admission ownership")
			}
			select {
			case <-reservationReady:
			default:
				t.Fatal("revalidation fixture did not own its reservation")
			}
			t.Cleanup(func() {
				connection.abortHTTP(server, httpConnectAbortSetupRace)
				assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
			})

			expected := httpConnectResponseFlowControlExpectation{
				backend:   backend,
				agentID:   agentID,
				connectID: connectID,
				mode:      httpConnectResponseModeAgentToServerByteWindowV1,
			}
			tt.mutate(connection, cancelBackend, replacementBackend)
			writer, installed := connection.installHTTPConnectResponseFlowControl(server, expected)
			if installed {
				t.Fatalf("%s revalidation installed response state, want rejection", tt.name)
			}
			if writer != nil {
				t.Fatalf("%s revalidation returned writer %p, want nil", tt.name, writer)
			}
			select {
			case <-done:
			default:
				t.Fatalf("%s revalidation did not synchronously release admission ownership", tt.name)
			}
			assertHTTPConnectFlowControlAllocatorUsage(t, allocator, 0, 0)
			connection.httpMu.Lock()
			installedState := connection.httpResponseFlowControl
			attachedWriter := connection.httpWriter
			terminal := connection.httpTerminal
			connection.httpMu.Unlock()
			if installedState != nil || attachedWriter != nil || !terminal {
				t.Fatalf("%s revalidation state = (%p, %p, %v), want (nil, nil, true)", tt.name, installedState, attachedWriter, terminal)
			}
			select {
			case <-connection.connected:
				t.Fatalf("%s revalidation signaled connected", tt.name)
			default:
			}
			written, _, _ := frontend.snapshot()
			if len(written) != 0 {
				t.Fatalf("%s revalidation wrote HTTP response %q, want none", tt.name, written)
			}
		})
	}
}

func TestHTTPConnectEnforcesResponseFlowControlMode(t *testing.T) {
	const (
		firstConnectID  = int64(6301)
		secondConnectID = int64(6302)
	)

	wantOffer := []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
	tests := []struct {
		name            string
		firstMode       httpConnectResponseMode
		secondMode      httpConnectResponseMode
		wantEstablished bool
	}{
		{
			name:            "response V1 to response V1",
			firstMode:       httpConnectResponseModeAgentToServerByteWindowV1,
			secondMode:      httpConnectResponseModeAgentToServerByteWindowV1,
			wantEstablished: true,
		},
		{
			name:       "response V1 to legacy",
			firstMode:  httpConnectResponseModeAgentToServerByteWindowV1,
			secondMode: httpConnectResponseModeLegacy,
		},
		{
			name:       "legacy to response V1",
			firstMode:  httpConnectResponseModeLegacy,
			secondMode: httpConnectResponseModeAgentToServerByteWindowV1,
		},
		{
			name:            "legacy to legacy",
			firstMode:       httpConnectResponseModeLegacy,
			secondMode:      httpConnectResponseModeLegacy,
			wantEstablished: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acceptedForMode := func(mode httpConnectResponseMode, offered []client.FlowControlFeature) []client.FlowControlFeature {
				switch mode {
				case httpConnectResponseModeLegacy:
					return nil
				case httpConnectResponseModeAgentToServerByteWindowV1:
					return slices.Clone(offered)
				default:
					t.Fatalf("unsupported test response mode %q", mode)
					return nil
				}
			}

			first := newHTTPConnectFlowControlDialFixture(t, true)
			firstOffer := slices.Clone(first.dialRequest.GetOfferedFlowControlFeatures())
			if !slices.Equal(firstOffer, wantOffer) {
				t.Fatalf("first DIAL_REQ offered flow-control features = %v, want %v", firstOffer, wantOffer)
			}

			consumer := startWriterTestBackendConsumer(t, first.proxyServer, first.backend, first.agentID, 1)
			consumer.recvCh <- &client.Packet{
				Type: client.PacketType_DIAL_RSP,
				Payload: &client.Packet_DialResponse{
					DialResponse: &client.DialResponse{
						Random:                      first.dialRequest.GetRandom(),
						ConnectID:                   firstConnectID,
						AcceptedFlowControlFeatures: acceptedForMode(tt.firstMode, firstOffer),
					},
				},
			}
			select {
			case <-first.pending.connected:
			case <-time.After(writerTestSafetyTimeout):
				t.Fatalf("server did not establish the first %q dial", tt.firstMode)
			}

			second := first.startDial(t)
			secondOffer := slices.Clone(second.dialRequest.GetOfferedFlowControlFeatures())
			if !slices.Equal(secondOffer, wantOffer) {
				t.Fatalf("second DIAL_REQ offered flow-control features = %v, want %v", secondOffer, wantOffer)
			}
			consumer.recvCh <- &client.Packet{
				Type: client.PacketType_DIAL_RSP,
				Payload: &client.Packet_DialResponse{
					DialResponse: &client.DialResponse{
						Random:                      second.dialRequest.GetRandom(),
						ConnectID:                   secondConnectID,
						AcceptedFlowControlFeatures: acceptedForMode(tt.secondMode, secondOffer),
					},
				},
			}

			if tt.wantEstablished {
				select {
				case <-second.pending.connected:
				case <-second.frontendConn.sink.closeObserved:
					written, _, _, _ := second.frontendConn.sink.snapshot()
					t.Fatalf("DIAL_RSP kept backend stream response mode %q but closed the tunnel after writing %q", tt.firstMode, written)
				case <-time.After(writerTestSafetyTimeout):
					t.Fatalf("server did not establish the second %q dial", tt.secondMode)
				}

				written, _, _, _ := second.frontendConn.sink.snapshot()
				if !bytes.Equal(written, []byte(httpConnectSuccessResponse)) {
					t.Fatalf("DIAL_RSP kept backend stream response mode %q and wrote %q, want complete successful CONNECT response", tt.firstMode, written)
				}
				if got, err := first.proxyServer.getFrontend(first.agentID, secondConnectID); err != nil || got != second.pending {
					t.Fatalf("second established connection = %p, %v; want %p", got, err, second.pending)
				}
				if got := second.pending.httpConnectResponseMode; got != tt.secondMode {
					t.Fatalf("second connection response mode = %q, want %q", got, tt.secondMode)
				}
			} else {
				select {
				case <-second.pending.connected:
					written, _, _, _ := second.frontendConn.sink.snapshot()
					t.Fatalf("DIAL_RSP changed backend stream response mode from %q to %q and established the tunnel with %q", tt.firstMode, tt.secondMode, written)
				case <-second.frontendConn.sink.closeObserved:
				case <-time.After(writerTestSafetyTimeout):
					t.Fatalf("server did not finish handling HTTP CONNECT response mode change from %q to %q", tt.firstMode, tt.secondMode)
				}

				written, _, _, _ := second.frontendConn.sink.snapshot()
				if bytes.HasPrefix(written, []byte(httpConnectSuccessResponse)) {
					t.Fatalf("DIAL_RSP changed backend stream response mode from %q to %q and wrote successful CONNECT response %q", tt.firstMode, tt.secondMode, written)
				}
				if _, err := first.proxyServer.getFrontend(first.agentID, secondConnectID); err == nil {
					t.Fatalf("DIAL_RSP changed backend stream response mode from %q to %q and published an established connection", tt.firstMode, tt.secondMode)
				}
			}
			if got := first.pending.httpConnectResponseMode; got != tt.firstMode {
				t.Fatalf("first connection response mode = %q, want %q", got, tt.firstMode)
			}
		})
	}
}

func httpConnectFlowControlDialRequest(t *testing.T, enabled bool) (*client.DialRequest, *ProxyClientConnection) {
	t.Helper()
	fixture := newHTTPConnectFlowControlDialFixture(t, enabled)
	return fixture.dialRequest, fixture.pending
}

type httpConnectFlowControlDialFixture struct {
	dialRequest   *client.DialRequest
	pending       *ProxyClientConnection
	proxyServer   *ProxyServer
	backend       *Backend
	agentID       string
	frontendConn  *observedHTTPConn
	dialRequests  chan *client.DialRequest
	cancelBackend context.CancelFunc
	target        string
}

func newHTTPConnectFlowControlDialFixture(t *testing.T, enabled bool) *httpConnectFlowControlDialFixture {
	return newHTTPConnectFlowControlDialFixtureWithHTTPWrite(t, enabled, true)
}

func newHTTPConnectFlowControlDialFixtureWithBlockedHTTPWrite(t *testing.T, enabled bool) *httpConnectFlowControlDialFixture {
	return newHTTPConnectFlowControlDialFixtureWithHTTPWrite(t, enabled, false)
}

func newHTTPConnectFlowControlDialFixtureWithHTTPWrite(
	t *testing.T,
	enabled bool,
	releaseInitialHTTPWrite bool,
) *httpConnectFlowControlDialFixture {
	t.Helper()

	const (
		agentID = "flow-control-contract-agent"
		target  = "flow-control-contract.invalid:443"
	)

	ctrl := gomock.NewController(t)
	backendConn := mockAgentConn(ctrl, agentID, nil)
	dialRequests := make(chan *client.DialRequest, 1)
	backendConn.EXPECT().Send(gomock.Any()).DoAndReturn(func(pkt *client.Packet) error {
		if pkt.Type == client.PacketType_CLOSE_REQ {
			return nil
		}
		if pkt.Type != client.PacketType_DIAL_REQ {
			t.Errorf("backend packet type = %v, want DIAL_REQ or CLOSE_REQ", pkt.Type)
			return nil
		}
		dialRequest := pkt.GetDialRequest()
		if dialRequest == nil {
			t.Error("DIAL_REQ packet has no dial request payload")
			return nil
		}
		select {
		case dialRequests <- dialRequest:
		default:
			t.Error("backend received duplicate DIAL_REQ")
		}
		return nil
	}).AnyTimes()

	backend, err := NewBackend(backendConn)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	backendContext, cancelBackend := context.WithCancel(backend.Context())
	backend.conn = &backendConnWithContext{
		AgentService_ConnectServer: backendConn,
		ctx:                        backendContext,
	}
	proxyServer := NewProxyServer(
		"",
		[]proxystrategies.ProxyStrategy{proxystrategies.ProxyStrategyDefault},
		1,
		nil,
		1,
	)
	proxyServer.SetHTTPConnectFlowControlEnabled(enabled)
	proxyServer.addBackend(backend)
	// The process policy is startup-only, but flipping the source value here
	// proves that the published backend stream owns an immutable snapshot.
	proxyServer.SetHTTPConnectFlowControlEnabled(!enabled)

	fixture := &httpConnectFlowControlDialFixture{
		proxyServer:   proxyServer,
		backend:       backend,
		agentID:       agentID,
		dialRequests:  dialRequests,
		cancelBackend: cancelBackend,
		target:        target,
	}
	return fixture.startDialWithHTTPWrite(t, releaseInitialHTTPWrite)
}

func (f *httpConnectFlowControlDialFixture) startDial(t *testing.T) *httpConnectFlowControlDialFixture {
	return f.startDialWithHTTPWrite(t, true)
}

func (f *httpConnectFlowControlDialFixture) startDialWithHTTPWrite(t *testing.T, releaseInitialHTTPWrite bool) *httpConnectFlowControlDialFixture {
	t.Helper()

	frontendConn := newObservedHTTPConn()
	if releaseInitialHTTPWrite {
		frontendConn.sink.release()
	}
	request := httptest.NewRequest(http.MethodConnect, "http://"+f.target, nil)
	request.Host = f.target
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		(&Tunnel{Server: f.proxyServer}).ServeHTTP(newHijackingResponseWriter(frontendConn), request)
	}()
	t.Cleanup(func() {
		f.cancelBackend()
		frontendConn.sink.release()
		_ = frontendConn.Close()
		select {
		case <-tunnelDone:
		case <-time.After(holTestSafetyTimeout):
			t.Errorf("HTTP tunnel did not exit during cleanup")
		}
	})

	var dialRequest *client.DialRequest
	select {
	case dialRequest = <-f.dialRequests:
	case <-time.After(holTestSafetyTimeout):
		t.Fatal("HTTP tunnel did not send DIAL_REQ")
	}

	f.proxyServer.PendingDial.mu.RLock()
	pending := f.proxyServer.PendingDial.pendingDial[dialRequest.GetRandom()]
	f.proxyServer.PendingDial.mu.RUnlock()
	if pending == nil {
		t.Fatal("sent DIAL_REQ has no pending logical dial")
	}

	return &httpConnectFlowControlDialFixture{
		dialRequest:   dialRequest,
		pending:       pending,
		proxyServer:   f.proxyServer,
		backend:       f.backend,
		agentID:       f.agentID,
		frontendConn:  frontendConn,
		dialRequests:  f.dialRequests,
		cancelBackend: f.cancelBackend,
		target:        f.target,
	}
}

// TestHTTPConnectRejectsAcceptedResponseFlowControlWithoutOffer starts at the
// PendingDial handoff with no feature offer recorded for the dial. The positive
// DIAL_RSP is therefore deliberately malformed: the server must reject it
// before connection publication or a successful CONNECT response.
func TestHTTPConnectRejectsAcceptedResponseFlowControlWithoutOffer(t *testing.T) {
	testHTTPConnectRejectsFlowControlResponse(t, nil, []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	})
}

// TestHTTPConnectRejectsDuplicateAcceptedResponseFlowControl starts after the
// PendingDial handoff with response V1 recorded as offered. Repeating that
// feature in the positive DIAL_RSP is malformed and must fail before HTTP 200.
func TestHTTPConnectRejectsDuplicateAcceptedResponseFlowControl(t *testing.T) {
	testHTTPConnectRejectsFlowControlResponse(t, []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}, []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	})
}

func testHTTPConnectRejectsFlowControlResponse(
	t *testing.T,
	offered []client.FlowControlFeature,
	accepted []client.FlowControlFeature,
) {
	t.Helper()

	const (
		agentID   = "malformed-flow-control-agent"
		dialID    = int64(6101)
		connectID = int64(6102)
	)

	proxyServer := newWriterTestServer()
	backend, _ := newWriterTestBackend(context.Background(), agentID)
	frontendHTTP := newWriterTestImmediateHTTP()
	connected := make(chan struct{})
	connection := &ProxyClientConnection{
		Mode:                ModeHTTPConnect,
		HTTP:                frontendHTTP,
		CloseHTTP:           frontendHTTP.close,
		connected:           connected,
		closed:              make(chan struct{}),
		dialID:              dialID,
		start:               time.Now(),
		backend:             backend,
		agentID:             agentID,
		httpInitialResponse: []byte(httpConnectSuccessResponse),

		offeredFlowControlFeatures: slices.Clone(offered),
	}
	proxyServer.PendingDial.Add(dialID, connection)
	consumer := startWriterTestBackendConsumer(t, proxyServer, backend, agentID, 1)

	consumer.recvCh <- &client.Packet{
		Type: client.PacketType_DIAL_RSP,
		Payload: &client.Packet_DialResponse{
			DialResponse: &client.DialResponse{
				Random:                      dialID,
				ConnectID:                   connectID,
				AcceptedFlowControlFeatures: slices.Clone(accepted),
			},
		},
	}

	select {
	case <-connected:
		written, _, _ := frontendHTTP.snapshot()
		t.Fatalf("DIAL_RSP with offered features %v and accepted features %v established the tunnel and wrote %q", offered, accepted, written)
	case <-frontendHTTP.closeCh:
	case <-time.After(writerTestSafetyTimeout):
		t.Fatalf("server did not finish malformed DIAL_RSP handling with offered features %v and accepted features %v", offered, accepted)
	}

	written, _, _ := frontendHTTP.snapshot()
	if bytes.HasPrefix(written, []byte(httpConnectSuccessResponse)) {
		t.Fatalf("DIAL_RSP with offered features %v and accepted features %v wrote successful CONNECT response %q", offered, accepted, written)
	}
	if _, err := proxyServer.getFrontend(agentID, connectID); err == nil {
		t.Fatalf("DIAL_RSP with offered features %v and accepted features %v published an established connection", offered, accepted)
	}
}
