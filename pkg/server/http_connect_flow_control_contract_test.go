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

func httpConnectFlowControlDialRequest(t *testing.T, enabled bool) (*client.DialRequest, *ProxyClientConnection) {
	t.Helper()
	fixture := newHTTPConnectFlowControlDialFixture(t, enabled)
	return fixture.dialRequest, fixture.pending
}

type httpConnectFlowControlDialFixture struct {
	dialRequest  *client.DialRequest
	pending      *ProxyClientConnection
	proxyServer  *ProxyServer
	backend      *Backend
	agentID      string
	frontendConn *observedHTTPConn
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
		if pkt.Type != client.PacketType_DIAL_REQ {
			t.Errorf("backend packet type = %v, want DIAL_REQ", pkt.Type)
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

	frontendConn := newObservedHTTPConn()
	frontendConn.sink.release()
	request := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
	request.Host = target
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		(&Tunnel{Server: proxyServer}).ServeHTTP(newHijackingResponseWriter(frontendConn), request)
	}()
	t.Cleanup(func() {
		cancelBackend()
		select {
		case <-tunnelDone:
		case <-time.After(holTestSafetyTimeout):
			t.Errorf("HTTP tunnel did not exit during cleanup")
		}
		_ = frontendConn.Close()
	})

	var dialRequest *client.DialRequest
	select {
	case dialRequest = <-dialRequests:
	case <-time.After(holTestSafetyTimeout):
		t.Fatal("HTTP tunnel did not send DIAL_REQ")
	}

	proxyServer.PendingDial.mu.RLock()
	pending := proxyServer.PendingDial.pendingDial[dialRequest.GetRandom()]
	proxyServer.PendingDial.mu.RUnlock()
	if pending == nil {
		t.Fatal("sent DIAL_REQ has no pending logical dial")
	}

	return &httpConnectFlowControlDialFixture{
		dialRequest:  dialRequest,
		pending:      pending,
		proxyServer:  proxyServer,
		backend:      backend,
		agentID:      agentID,
		frontendConn: frontendConn,
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
