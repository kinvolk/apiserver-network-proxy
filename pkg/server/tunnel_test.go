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
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server/proxystrategies"
)

type hijackResponseWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

func TestHTTPConnectTunnelRemovesEstablishedConnectionBeforeCloseRequestSend(t *testing.T) {
	ctrl := gomock.NewController(t)
	proxyServer := NewProxyServer("server", []proxystrategies.ProxyStrategy{proxystrategies.ProxyStrategyDefault}, 1, &AgentTokenAuthenticationOptions{}, xfrChannelSize)
	agentConn, backend := prepareAgentConnMD(t, ctrl, proxyServer, nil)

	dialRequestSent := make(chan *client.Packet, 1)
	closeRequestStarted := make(chan struct{})
	releaseCloseRequest := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseCloseRequest) })
	}
	defer release()

	agentConn.EXPECT().Send(gomock.AssignableToTypeOf(&client.Packet{})).DoAndReturn(func(pkt *client.Packet) error {
		switch pkt.Type {
		case client.PacketType_DIAL_REQ:
			dialRequestSent <- pkt
		case client.PacketType_CLOSE_REQ:
			close(closeRequestStarted)
			<-releaseCloseRequest
		default:
			t.Errorf("unexpected packet sent to backend: %s", pkt.Type)
		}
		return nil
	}).Times(2)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	w := &hijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverConn,
		rw:               bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn)),
	}
	r := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:443", nil)
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		(&Tunnel{Server: proxyServer}).ServeHTTP(w, r)
	}()

	var dialRequest *client.Packet
	select {
	case dialRequest = <-dialRequestSent:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DIAL_REQ")
	}

	// Make the HTTP 200 handshake fail after the backend has established the
	// logical connection. Cleanup must already be registered at this point.
	if err := clientConn.Close(); err != nil {
		t.Fatalf("failed to close frontend connection: %v", err)
	}
	frontend := proxyServer.PendingDial.Remove(dialRequest.GetDialRequest().Random)
	if frontend == nil {
		t.Fatal("pending HTTP frontend was not found")
	}
	const connectID int64 = 123
	frontend.connectID = connectID
	frontend.agentID = backend.GetAgentID()
	proxyServer.addEstablished(frontend.agentID, connectID, frontend)
	close(frontend.connected)

	select {
	case <-closeRequestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CLOSE_REQ after the failed HTTP handshake")
	}

	if got, err := proxyServer.getFrontend(frontend.agentID, connectID); err == nil || got != nil {
		t.Fatalf("established frontend remained tracked while CLOSE_REQ was blocked: got %v, err %v", got, err)
	}

	release()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP CONNECT handler to exit")
	}
}
