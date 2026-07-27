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

func TestHTTPConnectAcceptsOfferedResponseFlowControl(t *testing.T) {
	const connectID = int64(6201)

	fixture := newHTTPConnectFlowControlDialFixture(t, true)
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

	select {
	case <-fixture.pending.connected:
	case <-time.After(writerTestSafetyTimeout):
		t.Fatal("server did not establish DIAL_RSP accepting the recorded offer")
	}

	written, _, _, _ := fixture.frontendConn.sink.snapshot()
	if !bytes.Equal(written, []byte(httpConnectSuccessResponse)) {
		t.Fatalf("valid accepted DIAL_RSP wrote %q, want complete successful CONNECT response", written)
	}
	if got, err := fixture.proxyServer.getFrontend(fixture.agentID, connectID); err != nil || got != fixture.pending {
		t.Fatalf("established connection = %p, %v; want %p", got, err, fixture.pending)
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
	return fixture.startDial(t)
}

func (f *httpConnectFlowControlDialFixture) startDial(t *testing.T) *httpConnectFlowControlDialFixture {
	t.Helper()

	frontendConn := newObservedHTTPConn()
	frontendConn.sink.release()
	request := httptest.NewRequest(http.MethodConnect, "http://"+f.target, nil)
	request.Host = f.target
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		(&Tunnel{Server: f.proxyServer}).ServeHTTP(newHijackingResponseWriter(frontendConn), request)
	}()
	t.Cleanup(func() {
		f.cancelBackend()
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
