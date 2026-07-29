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

package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	serverpkg "sigs.k8s.io/apiserver-network-proxy/pkg/server"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server/proxystrategies"
	agentproto "sigs.k8s.io/apiserver-network-proxy/proto/agent"
	"sigs.k8s.io/apiserver-network-proxy/proto/header"
)

const (
	primaryHOLSafetyTimeout      = 5 * time.Second
	primaryHOLHTTPConnectSuccess = "HTTP/1.1 200 Connection Established\r\n\r\n"
)

// TestHTTPConnectResponseFlowControlPreventsHeadOfLineBlocking is the primary
// response-flow-control proof. It connects the production server backend loop
// to the production agent sender, so the offer, acceptance, endpoint reads,
// DATA frames, and WINDOW_UPDATE packets all use their real paths.
func TestHTTPConnectResponseFlowControlPreventsHeadOfLineBlocking(t *testing.T) {
	const (
		agentID     = "primary-hol-agent"
		targetProbe = "primary-hol-grant-probe.invalid:443"
		targetA     = "primary-hol-a.invalid:443"
		targetB     = "primary-hol-b.invalid:443"
	)

	stream := newPrimaryHOLStream(agentID)
	proxyServer := serverpkg.NewProxyServer(
		"primary-hol-server",
		[]proxystrategies.ProxyStrategy{proxystrategies.ProxyStrategyDefault},
		1,
		&serverpkg.AgentTokenAuthenticationOptions{},
		1,
	)
	proxyServer.SetHTTPConnectFlowControlEnabled(true)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- proxyServer.Connect(stream.server())
	}()
	waitForPrimaryHOLCondition(t, "server backend registration", func() bool {
		return proxyServer.BackendManagers[0].NumBackends() == 1
	})

	endpointProbe, endpointPeerProbe := net.Pipe()
	endpointA, endpointPeerA := net.Pipe()
	endpointB, endpointPeerB := net.Pipe()
	t.Cleanup(func() {
		_ = endpointProbe.Close()
		_ = endpointPeerProbe.Close()
		_ = endpointA.Close()
		_ = endpointPeerA.Close()
		_ = endpointB.Close()
		_ = endpointPeerB.Close()
	})

	endpointMu := sync.Mutex{}
	endpoints := map[string]net.Conn{
		targetProbe: endpointProbe,
		targetA:     endpointA,
		targetB:     endpointB,
	}
	clientSet := &ClientSet{
		clients:        make(map[string]*Client),
		xfrChannelSize: 1,
	}
	testClient := &Client{
		connManager:                      newConnectionManager(),
		cs:                               clientSet,
		stream:                           stream.client(),
		agentID:                          agentID,
		serverID:                         "primary-hol-server",
		drainCh:                          make(chan struct{}),
		stopCh:                           make(chan struct{}),
		probeInterval:                    time.Hour,
		enableAgentServerDataFlowControl: true,
		dialEndpoint: func(_, address string, _ time.Duration) (net.Conn, error) {
			endpointMu.Lock()
			defer endpointMu.Unlock()
			endpoint, ok := endpoints[address]
			if !ok {
				return nil, fmt.Errorf("unexpected or duplicate endpoint dial %q", address)
			}
			delete(endpoints, address)
			return endpoint, nil
		},
	}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		testClient.Serve()
	}()
	t.Cleanup(func() {
		close(testClient.stopCh)
		stream.stop()
		select {
		case <-clientDone:
		case <-time.After(primaryHOLSafetyTimeout):
			t.Error("agent client did not stop")
		}
		select {
		case <-serverDone:
		case <-time.After(primaryHOLSafetyTimeout):
			t.Error("server backend did not stop")
		}
	})

	// Closing a fully established probe tunnel gives the missing-grant red
	// state a terminal protocol checkpoint. Once its real CLOSE_REQ/CLOSE_RSP
	// handshake has removed the endpoint, no initial grant can arrive later.
	probeTunnel := startPrimaryHOLTunnel(t, proxyServer, targetProbe)
	probeConnection := waitForPrimaryHOLEndpointConnection(t, testClient, endpointProbe)
	if probeConnection.responseFlowControl == nil {
		t.Fatal("real agent accepted the probe dial without installing response flow control")
	}
	probeConnectID := probeConnection.connID
	probeTunnel.close(t, targetProbe)
	waitForPrimaryHOLCondition(t, "probe endpoint removal after CLOSE_REQ", func() bool {
		_, ok := testClient.connManager.Get(probeConnectID)
		return !ok
	})
	stream.requireNegotiatedInitialGrantBeforeClose(t, targetProbe, probeConnectID)

	tunnelA := startPrimaryHOLTunnel(t, proxyServer, targetA)
	endpointConnectionA := waitForPrimaryHOLEndpointConnection(t, testClient, endpointA)
	if endpointConnectionA.responseFlowControl == nil {
		t.Fatal("real agent accepted A without installing response flow control")
	}
	waitForPrimaryHOLCondition(t, "A receiving its initial response grant", func() bool {
		state := endpointConnectionA.responseFlowControl
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.sendLimit > 0
	})
	endpointConnectionA.responseFlowControl.mu.Lock()
	initialLimit := endpointConnectionA.responseFlowControl.sendLimit
	endpointConnectionA.responseFlowControl.mu.Unlock()
	if initialLimit > 1<<20 {
		t.Fatalf("initial response WINDOW_UPDATE limit = %d, want at most 1 MiB for this bounded proof", initialLimit)
	}

	payloadA := make([]byte, int(initialLimit)*4+37)
	for index := range payloadA {
		payloadA[index] = byte(index % 251)
	}
	writeADone := make(chan error, 1)
	go func() {
		_, err := endpointPeerA.Write(payloadA)
		writeADone <- err
	}()

	waitForPrimaryHOLCondition(t, "A exhausting its response credit", func() bool {
		state := endpointConnectionA.responseFlowControl
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.waiting && state.committedTotal == initialLimit && state.sentTotal == initialLimit
	})
	select {
	case err := <-writeADone:
		t.Fatalf("A endpoint wrote %d response bytes through a %d-byte window while its frontend was blocked: %v", len(payloadA), initialLimit, err)
	default:
	}

	stateA := endpointConnectionA.responseFlowControl
	stateA.mu.Lock()
	closedA := stateA.closed
	stateA.mu.Unlock()
	if closedA {
		t.Fatal("A closed at zero response credit, want an open backpressured connection")
	}
	if got, ok := testClient.connManager.Get(endpointConnectionA.connID); !ok || got != endpointConnectionA {
		t.Fatalf("A endpoint connection at zero credit = %p, %v; want live connection %p", got, ok, endpointConnectionA)
	}
	framesA, bytesA := stream.responseDATAStats(endpointConnectionA.connID)
	maxFramesA := int((initialLimit + agentToServerDataFrameSize - 1) / agentToServerDataFrameSize)
	if bytesA != initialLimit || framesA > maxFramesA {
		t.Fatalf("A response DATA at zero credit = %d bytes in %d frames, want %d bytes in at most %d frames", bytesA, framesA, initialLimit, maxFramesA)
	}

	tunnelB := startPrimaryHOLTunnel(t, proxyServer, targetB)
	endpointConnectionB := waitForPrimaryHOLEndpointConnection(t, testClient, endpointB)
	if endpointConnectionB.responseFlowControl == nil {
		t.Fatal("real agent established B without negotiated response flow control")
	}
	waitForPrimaryHOLCondition(t, "B receiving its initial response grant", func() bool {
		state := endpointConnectionB.responseFlowControl
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.sendLimit > 0
	})

	payloadB := []byte("B remains live while A is backpressured")
	writeBDone := make(chan error, 1)
	go func() {
		_, err := endpointPeerB.Write(payloadB)
		writeBDone <- err
	}()
	gotB := make([]byte, len(payloadB))
	readFullPrimaryHOL(t, tunnelB.frontend, gotB, "B tunneled response")
	if !bytes.Equal(gotB, payloadB) {
		t.Fatalf("B tunneled response = %q, want %q", gotB, payloadB)
	}
	select {
	case err := <-writeBDone:
		if err != nil {
			t.Fatalf("B endpoint response write: %v", err)
		}
	case <-time.After(primaryHOLSafetyTimeout):
		t.Fatal("B endpoint response write did not complete")
	}

	if got := proxyServer.BackendManagers[0].NumBackends(); got != 1 {
		t.Fatalf("backend streams while A is blocked and B is live = %d, want 1", got)
	}
	if got := len(testClient.connManager.List()); got != 2 {
		t.Fatalf("agent endpoint connections while A is blocked and B is live = %d, want 2", got)
	}
	stateA.mu.Lock()
	stillWaitingA := stateA.waiting
	committedA := stateA.committedTotal
	stateA.mu.Unlock()
	if !stillWaitingA || committedA != initialLimit {
		t.Fatalf("A state after B progress = {waiting: %v, committed: %d}, want zero-credit wait at %d", stillWaitingA, committedA, initialLimit)
	}
	select {
	case err := <-writeADone:
		t.Fatalf("A endpoint response completed before its frontend was released: %v", err)
	default:
	}

	gotA := make([]byte, len(payloadA))
	readFullPrimaryHOL(t, tunnelA.frontend, gotA, "resumed A tunneled response")
	if !bytes.Equal(gotA, payloadA) {
		for offset := range payloadA {
			if gotA[offset] != payloadA[offset] {
				t.Fatalf("resumed A response byte %d = 0x%02x, want 0x%02x", offset, gotA[offset], payloadA[offset])
			}
		}
		t.Fatal("resumed A response differs from endpoint payload")
	}
	select {
	case err := <-writeADone:
		if err != nil {
			t.Fatalf("A endpoint response write after release: %v", err)
		}
	case <-time.After(primaryHOLSafetyTimeout):
		t.Fatal("A endpoint response write did not resume after its frontend was released")
	}
	waitForPrimaryHOLCondition(t, "A accounting all resumed response bytes", func() bool {
		stateA.mu.Lock()
		defer stateA.mu.Unlock()
		want := uint64(len(payloadA))
		return stateA.committedTotal == want && stateA.sentTotal == want
	})
}

type primaryHOLStream struct {
	ctx    context.Context
	cancel context.CancelFunc

	toAgent  chan *client.Packet
	toServer chan *client.Packet

	mu       sync.Mutex
	received []*client.Packet
	sent     []*client.Packet
}

func newPrimaryHOLStream(agentID string) *primaryHOLStream {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(header.AgentID, agentID))
	ctx, cancel := context.WithCancel(ctx)
	return &primaryHOLStream{
		ctx:      ctx,
		cancel:   cancel,
		toAgent:  make(chan *client.Packet, 256),
		toServer: make(chan *client.Packet, 256),
	}
}

func (s *primaryHOLStream) client() agentproto.AgentService_ConnectClient {
	return &primaryHOLClientStream{primaryHOLStream: s}
}

func (s *primaryHOLStream) server() agentproto.AgentService_ConnectServer {
	return &primaryHOLServerStream{primaryHOLStream: s}
}

func (s *primaryHOLStream) stop() {
	s.cancel()
}

func (s *primaryHOLStream) recordReceived(packet *client.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, proto.Clone(packet).(*client.Packet))
}

func (s *primaryHOLStream) recordSent(packet *client.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, proto.Clone(packet).(*client.Packet))
}

func (s *primaryHOLStream) snapshot() (received, sent []*client.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.received), slices.Clone(s.sent)
}

func (s *primaryHOLStream) requireNegotiatedInitialGrantBeforeClose(t *testing.T, target string, connectID int64) {
	t.Helper()
	received, sent := s.snapshot()

	var dialRequest *client.DialRequest
	for _, packet := range received {
		if request := packet.GetDialRequest(); request != nil && request.GetAddress() == target {
			dialRequest = request
			break
		}
	}
	if dialRequest == nil {
		t.Fatalf("server packets = %v, want DIAL_REQ for %q", primaryHOLPacketTypes(received), target)
	}
	wantFeature := []client.FlowControlFeature{client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1}
	if got := dialRequest.GetOfferedFlowControlFeatures(); !slices.Equal(got, wantFeature) {
		t.Fatalf("real DIAL_REQ offered flow-control features = %v, want %v", got, wantFeature)
	}

	var dialResponse *client.DialResponse
	for _, packet := range sent {
		if response := packet.GetDialResponse(); response != nil && response.GetRandom() == dialRequest.GetRandom() {
			dialResponse = response
			break
		}
	}
	if dialResponse == nil {
		t.Fatalf("agent packets = %v, want DIAL_RSP for dial %d", primaryHOLPacketTypes(sent), dialRequest.GetRandom())
	}
	if got := dialResponse.GetAcceptedFlowControlFeatures(); !slices.Equal(got, wantFeature) {
		t.Fatalf("real DIAL_RSP accepted flow-control features = %v, want %v", got, wantFeature)
	}
	if got := dialResponse.GetConnectID(); got != connectID {
		t.Fatalf("real DIAL_RSP connection ID = %d, want probe connection %d", got, connectID)
	}

	grantIndex := -1
	closeIndex := -1
	for index, packet := range received {
		if update := packet.GetWindowUpdate(); update != nil && update.GetConnectId() == connectID && update.GetMaxDataOffset() > 0 && grantIndex == -1 {
			grantIndex = index
		}
		if request := packet.GetCloseRequest(); request != nil && request.GetConnectID() == connectID {
			closeIndex = index
			break
		}
	}
	if closeIndex == -1 {
		t.Fatalf("server packets = %v, want CLOSE_REQ for probe connection %d", primaryHOLPacketTypes(received), connectID)
	}
	if grantIndex == -1 || grantIndex > closeIndex {
		t.Fatalf("server packets through probe CLOSE_REQ = %v, want positive initial WINDOW_UPDATE for connection %d before CLOSE_REQ", primaryHOLPacketTypes(received[:closeIndex+1]), connectID)
	}
}

func (s *primaryHOLStream) responseDATAStats(connectID int64) (frames int, bytes uint64) {
	_, sent := s.snapshot()
	for _, packet := range sent {
		if data := packet.GetData(); data != nil && data.GetConnectID() == connectID {
			frames++
			bytes += uint64(len(data.GetData()))
		}
	}
	return frames, bytes
}

type primaryHOLClientStream struct {
	grpc.ClientStream
	*primaryHOLStream
}

func (s *primaryHOLClientStream) Send(packet *client.Packet) error {
	s.recordSent(packet)
	select {
	case s.toServer <- packet:
		return nil
	case <-s.ctx.Done():
		return io.EOF
	}
}

func (s *primaryHOLClientStream) Recv() (*client.Packet, error) {
	select {
	case packet := <-s.toAgent:
		s.recordReceived(packet)
		return packet, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

type primaryHOLServerStream struct {
	grpc.ServerStream
	*primaryHOLStream
}

func (s *primaryHOLServerStream) Send(packet *client.Packet) error {
	select {
	case s.toAgent <- packet:
		return nil
	case <-s.ctx.Done():
		return io.EOF
	}
}

func (s *primaryHOLServerStream) Recv() (*client.Packet, error) {
	select {
	case packet := <-s.toServer:
		return packet, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

func (s *primaryHOLServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (s *primaryHOLServerStream) Context() context.Context {
	return s.ctx
}

type primaryHOLTunnel struct {
	frontend   net.Conn
	serverConn net.Conn
	done       chan struct{}
	closeOnce  sync.Once
}

func startPrimaryHOLTunnel(t *testing.T, proxyServer *serverpkg.ProxyServer, target string) *primaryHOLTunnel {
	t.Helper()
	serverConn, frontend := net.Pipe()
	done := make(chan struct{})
	request := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
	request.Host = target
	go func() {
		defer close(done)
		(&serverpkg.Tunnel{Server: proxyServer}).ServeHTTP(newPrimaryHOLResponseWriter(serverConn), request)
	}()
	tunnel := &primaryHOLTunnel{
		frontend:   frontend,
		serverConn: serverConn,
		done:       done,
	}
	t.Cleanup(func() { tunnel.close(t, target) })

	response := make([]byte, len(primaryHOLHTTPConnectSuccess))
	readFullPrimaryHOL(t, frontend, response, target+" CONNECT response")
	if got := string(response); got != primaryHOLHTTPConnectSuccess {
		t.Fatalf("%s CONNECT response = %q, want %q", target, got, primaryHOLHTTPConnectSuccess)
	}
	return tunnel
}

func (tunnel *primaryHOLTunnel) close(t *testing.T, target string) {
	t.Helper()
	tunnel.closeOnce.Do(func() {
		// Closing only the frontend first drives the production CLOSE_REQ and
		// CLOSE_RSP lifecycle. The server-side pipe remains live until ServeHTTP
		// returns so the close handshake cannot be manufactured by test cleanup.
		_ = tunnel.frontend.Close()
		select {
		case <-tunnel.done:
			_ = tunnel.serverConn.Close()
		case <-time.After(primaryHOLSafetyTimeout):
			_ = tunnel.serverConn.Close()
			t.Fatalf("HTTP tunnel for %q did not stop after frontend close", target)
		}
	})
}

type primaryHOLResponseWriter struct {
	header http.Header
	conn   net.Conn
	bufrw  *bufio.ReadWriter
}

func newPrimaryHOLResponseWriter(conn net.Conn) *primaryHOLResponseWriter {
	return &primaryHOLResponseWriter{
		header: make(http.Header),
		conn:   conn,
		bufrw:  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
}

func (w *primaryHOLResponseWriter) Header() http.Header         { return w.header }
func (w *primaryHOLResponseWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }
func (w *primaryHOLResponseWriter) WriteHeader(int)             {}
func (w *primaryHOLResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.bufrw, nil
}

func waitForPrimaryHOLEndpointConnection(t *testing.T, testClient *Client, endpoint net.Conn) *endpointConn {
	t.Helper()
	var found *endpointConn
	waitForPrimaryHOLCondition(t, "agent endpoint connection publication", func() bool {
		for _, connection := range testClient.connManager.List() {
			if connection.conn == endpoint {
				found = connection
				return true
			}
		}
		return false
	})
	return found
}

func waitForPrimaryHOLCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(primaryHOLSafetyTimeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func readFullPrimaryHOL(t *testing.T, conn net.Conn, dst []byte, description string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(primaryHOLSafetyTimeout)); err != nil {
		t.Fatalf("set %s read deadline: %v", description, err)
	}
	if _, err := io.ReadFull(conn, dst); err != nil {
		t.Fatalf("read %s: %v", description, err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear %s read deadline: %v", description, err)
	}
}

func primaryHOLPacketTypes(packets []*client.Packet) []client.PacketType {
	types := make([]client.PacketType, 0, len(packets))
	for _, packet := range packets {
		types = append(types, packet.GetType())
	}
	return types
}
