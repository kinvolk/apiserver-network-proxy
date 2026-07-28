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
	"bytes"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	agentproto "sigs.k8s.io/apiserver-network-proxy/proto/agent"
)

const agentFlowControlTestSafetyTimeout = 5 * time.Second

func TestHTTPConnectResponseFlowControlWaitsForInitialGrant(t *testing.T) {
	const (
		dialID   = int64(7101)
		target   = "flow-control-endpoint.invalid:443"
		protocol = "tcp"
	)
	wantAccepted := []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
	payload := []byte("response bytes")

	stopCh := make(chan struct{})
	clientSet := &ClientSet{
		clients:        make(map[string]*Client),
		stopCh:         stopCh,
		xfrChannelSize: 1,
	}
	endpoint, peer := net.Pipe()
	observedEndpoint := &readObservedConn{
		Conn:        endpoint,
		readStarted: make(chan struct{}),
	}
	clientStream, serverStream := pipe()
	dialResponseObserved := make(chan responseFlowControlDialObservation, 1)
	testClient := &Client{
		connManager:                  newConnectionManager(),
		stopCh:                       stopCh,
		cs:                           clientSet,
		enableHTTPConnectFlowControl: true,
		dialEndpoint: func(_, _ string, _ time.Duration) (net.Conn, error) {
			return observedEndpoint, nil
		},
	}
	testClient.stream = &responseFlowControlObservingStream{
		AgentService_ConnectClient: clientStream,
		client:                     testClient,
		observed:                   dialResponseObserved,
	}

	t.Cleanup(func() {
		for _, eConn := range testClient.connManager.List() {
			if state := eConn.responseFlowControl; state != nil {
				state.mu.Lock()
				state.closed = true
				if state.changed != nil {
					state.changed.Broadcast()
				}
				state.mu.Unlock()
			}
		}
		_ = observedEndpoint.Close()
		_ = peer.Close()
		close(stopCh)
	})

	go testClient.Serve()

	dialRequest := newDialPacket(protocol, target, dialID)
	dialRequest.GetDialRequest().OfferedFlowControlFeatures = slices.Clone(wantAccepted)
	if err := serverStream.Send(dialRequest); err != nil {
		t.Fatalf("send DIAL_REQ: %v", err)
	}

	dialResponsePacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive DIAL_RSP: %v", err)
	}
	if got := dialResponsePacket.GetType(); got != client.PacketType_DIAL_RSP {
		t.Fatalf("agent packet type = %v, want DIAL_RSP", got)
	}
	dialResponse := dialResponsePacket.GetDialResponse()
	if got := dialResponse.GetRandom(); got != dialID {
		t.Fatalf("DIAL_RSP random = %d, want %d", got, dialID)
	}
	if got := dialResponse.GetError(); got != "" {
		t.Fatalf("DIAL_RSP error = %q, want successful endpoint dial", got)
	}
	if got := dialResponse.GetAcceptedFlowControlFeatures(); !slices.Equal(got, wantAccepted) {
		t.Fatalf("DIAL_RSP accepted flow-control features = %v, want offered supported subset %v", got, wantAccepted)
	}

	observation := <-dialResponseObserved
	if !observation.connectionPresent {
		t.Fatal("successful DIAL_RSP was sent before publishing its endpoint connection")
	}
	if observation.state == nil {
		t.Fatal("successful negotiated DIAL_RSP was sent before installing response flow-control state")
	}
	if observation.sendLimit != 0 || observation.committedTotal != 0 {
		t.Fatalf("state before successful DIAL_RSP = {sendLimit: %d, committedTotal: %d}, want both zero", observation.sendLimit, observation.committedTotal)
	}

	writeResult := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeResult <- err
	}()
	waitForResponseFlowControlWait(t, observation.state, observedEndpoint.readStarted)

	windowUpdate := &client.Packet{
		Type: client.PacketType_WINDOW_UPDATE,
		Payload: &client.Packet_WindowUpdate{
			WindowUpdate: &client.WindowUpdate{
				ConnectId:     dialResponse.GetConnectID(),
				MaxDataOffset: uint64(len(payload)),
			},
		},
	}
	if err := serverStream.Send(windowUpdate); err != nil {
		t.Fatalf("send initial WINDOW_UPDATE: %v", err)
	}

	dataPacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive granted response DATA: %v", err)
	}
	if got := dataPacket.GetType(); got != client.PacketType_DATA {
		t.Fatalf("agent packet after initial grant = %v, want DATA", got)
	}
	if got := dataPacket.GetData().GetConnectID(); got != dialResponse.GetConnectID() {
		t.Fatalf("response DATA connect ID = %d, want %d", got, dialResponse.GetConnectID())
	}
	if got := dataPacket.GetData().GetData(); !bytes.Equal(got, payload) {
		t.Fatalf("response DATA = %q, want %q", got, payload)
	}
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("write endpoint response: %v", err)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("endpoint response write did not complete after matching grant")
	}

	observation.state.mu.Lock()
	committedTotal := observation.state.committedTotal
	observation.state.mu.Unlock()
	if want := uint64(len(payload)); committedTotal != want {
		t.Fatalf("committed response bytes = %d, want %d", committedTotal, want)
	}
	waitForResponseFlowControlWait(t, observation.state, nil)

	if err := serverStream.Send(newClosePacket(dialResponse.GetConnectID())); err != nil {
		t.Fatalf("send CLOSE_REQ: %v", err)
	}
	closeResponsePacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive CLOSE_RSP: %v", err)
	}
	if got := closeResponsePacket.GetType(); got != client.PacketType_CLOSE_RSP {
		t.Fatalf("agent packet after CLOSE_REQ = %v, want CLOSE_RSP", got)
	}
	if got := closeResponsePacket.GetCloseResponse().GetConnectID(); got != dialResponse.GetConnectID() {
		t.Fatalf("CLOSE_RSP connect ID = %d, want %d", got, dialResponse.GetConnectID())
	}
	waitForConnectionDeletion(t, testClient, dialResponse.GetConnectID())
}

func TestHTTPConnectResponseFlowControlRequiresOffer(t *testing.T) {
	const (
		dialID   = int64(7102)
		target   = "legacy-flow-control-endpoint.invalid:443"
		protocol = "tcp"
	)
	payload := []byte("legacy response bytes")

	stopCh := make(chan struct{})
	clientSet := &ClientSet{
		clients:        make(map[string]*Client),
		stopCh:         stopCh,
		xfrChannelSize: 1,
	}
	endpoint, peer := net.Pipe()
	clientStream, serverStream := pipe()
	dialResponseObserved := make(chan responseFlowControlDialObservation, 1)
	testClient := &Client{
		connManager:                  newConnectionManager(),
		stopCh:                       stopCh,
		cs:                           clientSet,
		enableHTTPConnectFlowControl: true,
		dialEndpoint: func(_, _ string, _ time.Duration) (net.Conn, error) {
			return endpoint, nil
		},
	}
	testClient.stream = &responseFlowControlObservingStream{
		AgentService_ConnectClient: clientStream,
		client:                     testClient,
		observed:                   dialResponseObserved,
	}

	t.Cleanup(func() {
		_ = endpoint.Close()
		_ = peer.Close()
		close(stopCh)
	})

	go testClient.Serve()

	if err := serverStream.Send(newDialPacket(protocol, target, dialID)); err != nil {
		t.Fatalf("send DIAL_REQ without flow-control offer: %v", err)
	}

	dialResponsePacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive DIAL_RSP: %v", err)
	}
	if got := dialResponsePacket.GetType(); got != client.PacketType_DIAL_RSP {
		t.Fatalf("agent packet type = %v, want DIAL_RSP", got)
	}
	dialResponse := dialResponsePacket.GetDialResponse()
	if got := dialResponse.GetRandom(); got != dialID {
		t.Fatalf("DIAL_RSP random = %d, want %d", got, dialID)
	}
	if got := dialResponse.GetError(); got != "" {
		t.Fatalf("DIAL_RSP error = %q, want successful endpoint dial", got)
	}
	if got := dialResponse.GetAcceptedFlowControlFeatures(); len(got) != 0 {
		t.Fatalf("enabled agent accepted unoffered flow-control features %v", got)
	}

	observation := <-dialResponseObserved
	if !observation.connectionPresent {
		t.Fatal("successful DIAL_RSP was sent before publishing its endpoint connection")
	}
	if observation.state != nil {
		t.Fatal("enabled agent installed response flow-control state without an offer")
	}

	writeResult := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeResult <- err
	}()

	dataPacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive legacy response DATA without WINDOW_UPDATE: %v", err)
	}
	if got := dataPacket.GetType(); got != client.PacketType_DATA {
		t.Fatalf("agent packet without flow-control offer = %v, want DATA", got)
	}
	if got := dataPacket.GetData().GetConnectID(); got != dialResponse.GetConnectID() {
		t.Fatalf("legacy response DATA connect ID = %d, want %d", got, dialResponse.GetConnectID())
	}
	if got := dataPacket.GetData().GetData(); !bytes.Equal(got, payload) {
		t.Fatalf("legacy response DATA = %q, want %q", got, payload)
	}
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("write endpoint response: %v", err)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("legacy endpoint response write did not complete")
	}

	if err := serverStream.Send(newClosePacket(dialResponse.GetConnectID())); err != nil {
		t.Fatalf("send CLOSE_REQ: %v", err)
	}
	closeResponsePacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive CLOSE_RSP: %v", err)
	}
	if got := closeResponsePacket.GetType(); got != client.PacketType_CLOSE_RSP {
		t.Fatalf("agent packet after CLOSE_REQ = %v, want CLOSE_RSP", got)
	}
	if got := closeResponsePacket.GetCloseResponse().GetConnectID(); got != dialResponse.GetConnectID() {
		t.Fatalf("CLOSE_RSP connect ID = %d, want %d", got, dialResponse.GetConnectID())
	}
	waitForConnectionDeletion(t, testClient, dialResponse.GetConnectID())
}

func TestHTTPConnectResponseFlowControlUsesMonotonicCumulativeLimits(t *testing.T) {
	const (
		initialLimit = uint64(8)
		higherLimit  = uint64(13)
		maxFrameSize = 1 << 12
	)

	state := newAgentToServerFlowControlState()
	t.Cleanup(state.close)

	state.advanceSendLimit(initialLimit)
	readSize, ok := state.nextReadSize(maxFrameSize)
	if !ok || readSize != int(initialLimit) {
		t.Fatalf("initial read allowance = %d, %t, want %d, true", readSize, ok, initialLimit)
	}
	if !state.commitRead(readSize) {
		t.Fatalf("commit initial read of %d bytes was rejected", readSize)
	}

	type allowanceResult struct {
		size int
		ok   bool
	}
	nextAllowance := make(chan allowanceResult, 1)
	go func() {
		size, ok := state.nextReadSize(maxFrameSize)
		nextAllowance <- allowanceResult{size: size, ok: ok}
	}()
	waitForResponseFlowControlWait(t, state, nil)

	for _, update := range []struct {
		name  string
		limit uint64
	}{
		{name: "duplicate", limit: initialLimit},
		{name: "lower", limit: initialLimit - 1},
	} {
		t.Run(update.name, func(t *testing.T) {
			state.advanceSendLimit(update.limit)
			state.mu.Lock()
			sendLimit := state.sendLimit
			committedTotal := state.committedTotal
			state.mu.Unlock()
			if sendLimit != initialLimit || committedTotal != initialLimit {
				t.Fatalf("state after cumulative limit %d = {sendLimit: %d, committedTotal: %d}, want both %d", update.limit, sendLimit, committedTotal, initialLimit)
			}
		})
	}

	state.advanceSendLimit(higherLimit)
	select {
	case result := <-nextAllowance:
		want := int(higherLimit - initialLimit)
		if !result.ok || result.size != want {
			t.Fatalf("read allowance after cumulative limit increase = %d, %t, want delta %d, true", result.size, result.ok, want)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("higher cumulative limit did not wake the waiting response producer")
	}
}

func TestHTTPConnectResponseFlowControlWindowUpdateWakesOnlyTarget(t *testing.T) {
	const (
		firstConnectID  = int64(7201)
		secondConnectID = int64(7202)
		firstLimit      = uint64(11)
		secondLimit     = uint64(7)
		maxFrameSize    = 1 << 12
	)

	stopCh := make(chan struct{})
	clientSet := &ClientSet{
		clients: make(map[string]*Client),
		stopCh:  stopCh,
	}
	clientStream, serverStream := pipe()
	testClient := &Client{
		connManager:   newConnectionManager(),
		stopCh:        stopCh,
		cs:            clientSet,
		stream:        clientStream,
		probeInterval: time.Hour,
	}

	firstState := newAgentToServerFlowControlState()
	secondState := newAgentToServerFlowControlState()
	addConnection := func(connectID int64, state *agentToServerFlowControlState) {
		endpoint := &endpointConn{
			connID:              connectID,
			responseFlowControl: state,
		}
		endpoint.cleanFunc = func() {
			state.close()
			testClient.connManager.Delete(connectID)
		}
		testClient.connManager.Add(connectID, endpoint)
	}
	addConnection(firstConnectID, firstState)
	addConnection(secondConnectID, secondState)

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		testClient.Serve()
	}()
	t.Cleanup(func() {
		secondState.close()
		firstState.close()
		close(stopCh)
		// fakeStream has no close operation; wake Recv so Serve can observe stopCh.
		_ = serverStream.Send(&client.Packet{Type: client.PacketType_DRAIN})
		select {
		case <-serveDone:
		case <-time.After(agentFlowControlTestSafetyTimeout):
			t.Error("agent client did not stop after WINDOW_UPDATE routing test")
		}
	})

	type allowanceResult struct {
		size int
		ok   bool
	}
	startAllowanceWait := func(state *agentToServerFlowControlState) <-chan allowanceResult {
		result := make(chan allowanceResult, 1)
		go func() {
			size, ok := state.nextReadSize(maxFrameSize)
			result <- allowanceResult{size: size, ok: ok}
		}()
		return result
	}
	firstAllowance := startAllowanceWait(firstState)
	secondAllowance := startAllowanceWait(secondState)
	waitForResponseFlowControlWait(t, firstState, nil)
	waitForResponseFlowControlWait(t, secondState, nil)

	windowUpdate := func(connectID int64, limit uint64) *client.Packet {
		return &client.Packet{
			Type: client.PacketType_WINDOW_UPDATE,
			Payload: &client.Packet_WindowUpdate{
				WindowUpdate: &client.WindowUpdate{
					ConnectId:     connectID,
					MaxDataOffset: limit,
				},
			},
		}
	}
	if err := serverStream.Send(windowUpdate(firstConnectID, firstLimit)); err != nil {
		t.Fatalf("send first connection WINDOW_UPDATE: %v", err)
	}
	select {
	case result := <-firstAllowance:
		if !result.ok || result.size != int(firstLimit) {
			t.Fatalf("first connection allowance = %d, %t, want %d, true", result.size, result.ok, firstLimit)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("first connection did not wake for its WINDOW_UPDATE")
	}

	secondState.mu.Lock()
	secondSendLimit := secondState.sendLimit
	secondCommittedTotal := secondState.committedTotal
	secondWaiting := secondState.waiting
	secondState.mu.Unlock()
	if secondSendLimit != 0 || secondCommittedTotal != 0 || !secondWaiting {
		t.Fatalf("untargeted connection state = {sendLimit: %d, committedTotal: %d, waiting: %t}, want 0, 0, true", secondSendLimit, secondCommittedTotal, secondWaiting)
	}
	select {
	case result := <-secondAllowance:
		t.Fatalf("untargeted connection received allowance %d, %t", result.size, result.ok)
	default:
	}

	if err := serverStream.Send(windowUpdate(secondConnectID, secondLimit)); err != nil {
		t.Fatalf("send second connection WINDOW_UPDATE: %v", err)
	}
	select {
	case result := <-secondAllowance:
		if !result.ok || result.size != int(secondLimit) {
			t.Fatalf("second connection allowance = %d, %t, want %d, true", result.size, result.ok, secondLimit)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("second connection did not wake for its WINDOW_UPDATE")
	}
}

type responseFlowControlDialObservation struct {
	connectionPresent bool
	state             *agentToServerFlowControlState
	sendLimit         uint64
	committedTotal    uint64
}

type responseFlowControlObservingStream struct {
	agentproto.AgentService_ConnectClient
	client   *Client
	observed chan<- responseFlowControlDialObservation
}

func (s *responseFlowControlObservingStream) Send(packet *client.Packet) error {
	if packet.GetType() == client.PacketType_DIAL_RSP {
		response := packet.GetDialResponse()
		eConn, ok := s.client.connManager.Get(response.GetConnectID())
		observation := responseFlowControlDialObservation{connectionPresent: ok}
		if ok {
			observation.state = eConn.responseFlowControl
			if observation.state != nil {
				observation.state.mu.Lock()
				observation.sendLimit = observation.state.sendLimit
				observation.committedTotal = observation.state.committedTotal
				observation.state.mu.Unlock()
			}
		}
		s.observed <- observation
	}
	return s.AgentService_ConnectClient.Send(packet)
}

func waitForResponseFlowControlWait(t *testing.T, state *agentToServerFlowControlState, forbiddenRead <-chan struct{}) {
	t.Helper()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(agentFlowControlTestSafetyTimeout)
	defer timeout.Stop()

	for {
		state.mu.Lock()
		waiting := state.waiting
		closed := state.closed
		state.mu.Unlock()
		if waiting {
			if forbiddenRead != nil {
				select {
				case <-forbiddenRead:
					t.Fatal("endpoint Read started while response flow-control credit was zero")
				default:
				}
			}
			return
		}
		if closed {
			t.Fatal("response flow-control state closed before entering credit wait")
		}

		select {
		case <-forbiddenRead:
			t.Fatal("endpoint Read started before waiting for positive response flow-control credit")
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("endpoint-read producer did not enter response flow-control credit wait")
		}
	}
}

type readObservedConn struct {
	net.Conn
	readOnce    sync.Once
	readStarted chan struct{}
}

func (c *readObservedConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}
