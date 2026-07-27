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
	dialRequest := httpConnectFlowControlDialRequest(t, true)
	want := []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
	if got := dialRequest.GetOfferedFlowControlFeatures(); !slices.Equal(got, want) {
		t.Fatalf("DIAL_REQ offered flow-control features = %v, want %v", got, want)
	}
}

func TestHTTPConnectDialDoesNotOfferFlowControlWhenDisabled(t *testing.T) {
	dialRequest := httpConnectFlowControlDialRequest(t, false)
	if got := dialRequest.GetOfferedFlowControlFeatures(); len(got) != 0 {
		t.Fatalf("DIAL_REQ offered flow-control features = %v, want no offer", got)
	}
}

func httpConnectFlowControlDialRequest(t *testing.T, enabled bool) *client.DialRequest {
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

	return dialRequest
}
