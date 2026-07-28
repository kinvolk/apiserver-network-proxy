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
	"errors"
	"io"
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

func TestHTTPConnectResponseFlowControlFramesEOFBytesBeforeClose(t *testing.T) {
	const (
		dialID   = int64(7103)
		target   = "flow-control-eof-endpoint.invalid:443"
		protocol = "tcp"
		tailSize = 17
	)
	payload := make([]byte, agentToServerDataFrameSize+tailSize)
	for index := range payload {
		payload[index] = byte(index % 251)
	}

	stopCh := make(chan struct{})
	clientSet := &ClientSet{
		clients:        make(map[string]*Client),
		stopCh:         stopCh,
		xfrChannelSize: 1,
	}
	// The pipe supplies the embedded net.Conn methods; response bytes come
	// directly from dataAndEOFConn.Read.
	endpointBase, endpointPeer := net.Pipe()
	endpoint := &dataAndEOFConn{
		Conn:      endpointBase,
		remaining: payload,
	}
	clientStream, serverStream := pipe()
	testClient := &Client{
		connManager:                  newConnectionManager(),
		stopCh:                       stopCh,
		cs:                           clientSet,
		stream:                       clientStream,
		probeInterval:                time.Hour,
		enableHTTPConnectFlowControl: true,
		dialEndpoint: func(_, _ string, _ time.Duration) (net.Conn, error) {
			return endpoint, nil
		},
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		testClient.Serve()
	}()
	t.Cleanup(func() {
		_ = endpoint.Close()
		_ = endpointPeer.Close()
		close(stopCh)
		// fakeStream has no close operation; wake Recv so Serve observes stopCh.
		_ = serverStream.Send(&client.Packet{Type: client.PacketType_DRAIN})
		select {
		case <-serveDone:
		case <-time.After(agentFlowControlTestSafetyTimeout):
			t.Error("agent client did not stop after EOF response test")
		}
	})

	dialRequest := newDialPacket(protocol, target, dialID)
	dialRequest.GetDialRequest().OfferedFlowControlFeatures = []client.FlowControlFeature{
		client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1,
	}
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
	if got := dialResponse.GetAcceptedFlowControlFeatures(); !slices.Equal(got, dialRequest.GetDialRequest().GetOfferedFlowControlFeatures()) {
		t.Fatalf("DIAL_RSP accepted flow-control features = %v, want offered response V1", got)
	}

	if err := serverStream.Send(newWindowUpdatePacket(dialResponse.GetConnectID(), uint64(len(payload)))); err != nil {
		t.Fatalf("send initial WINDOW_UPDATE: %v", err)
	}
	// The first Read is buffer-bound; the second is credit-bound by the tail.
	for index, want := range [][]byte{payload[:agentToServerDataFrameSize], payload[agentToServerDataFrameSize:]} {
		packet, err := serverStream.Recv()
		if err != nil {
			t.Fatalf("receive response DATA frame %d: %v", index+1, err)
		}
		if got := packet.GetType(); got != client.PacketType_DATA {
			t.Fatalf("agent packet %d after grant = %v, want DATA before close", index+1, got)
		}
		if got := packet.GetData().GetConnectID(); got != dialResponse.GetConnectID() {
			t.Fatalf("response DATA frame %d connect ID = %d, want %d", index+1, got, dialResponse.GetConnectID())
		}
		got := packet.GetData().GetData()
		if len(got) != len(want) {
			t.Fatalf("response DATA frame %d length = %d, want %d", index+1, len(got), len(want))
		}
		for offset := range want {
			if got[offset] != want[offset] {
				t.Fatalf("response DATA frame %d byte %d = 0x%02x, want 0x%02x", index+1, offset, got[offset], want[offset])
			}
		}
	}

	closeResponsePacket, err := serverStream.Recv()
	if err != nil {
		t.Fatalf("receive CLOSE_RSP after EOF bytes: %v", err)
	}
	if got := closeResponsePacket.GetType(); got != client.PacketType_CLOSE_RSP {
		t.Fatalf("agent packet after EOF response DATA = %v, want CLOSE_RSP", got)
	}
	if got := closeResponsePacket.GetCloseResponse().GetConnectID(); got != dialResponse.GetConnectID() {
		t.Fatalf("CLOSE_RSP connect ID = %d, want %d", got, dialResponse.GetConnectID())
	}
	waitForConnectionDeletion(t, testClient, dialResponse.GetConnectID())
	if !slices.Equal(endpoint.readSizes, []int{agentToServerDataFrameSize, tailSize}) {
		t.Fatalf("endpoint Read sizes = %v, want buffer-bound %d then credit-bound %d", endpoint.readSizes, agentToServerDataFrameSize, tailSize)
	}
}

func TestHTTPConnectResponseFlowControlCommitsBeforeQueuePublication(t *testing.T) {
	const connectID = int64(7104)
	firstPayload := []byte("first response payload")
	queuedPayload := []byte("queued response payload")
	blockedPayload := []byte("payload blocked before queue publication")
	grantedBytes := len(firstPayload) + len(queuedPayload) + len(blockedPayload)

	state := newAgentToServerFlowControlState()
	state.advanceSendLimit(uint64(grantedBytes))
	stopCh := make(chan struct{})
	// Blocking the first DATA Send fills this depth-one queue with queuedPayload,
	// leaving blockedPayload stuck at publication. Moving commitRead below the
	// queue send therefore leaves committedTotal short of grantedBytes.
	sendCh := make(chan []byte, 1)
	sendDone := make(chan struct{})
	// The pipe supplies only the embedded net.Conn methods for the scripted reader.
	endpointBase, endpointPeer := net.Pipe()
	endpoint := &zeroThenChunkedConn{
		Conn:              endpointBase,
		chunks:            [][]byte{firstPayload, queuedPayload, blockedPayload},
		allPayloadRead:    make(chan struct{}),
		readBeyondPayload: make(chan struct{}),
	}
	stream := &observingDataSendBlockingStream{
		dataSends:   make(chan []byte, 3),
		sendRelease: make(chan struct{}),
	}
	eConn := &endpointConn{
		conn:                endpoint,
		connID:              connectID,
		cleanFunc:           func() {},
		responseFlowControl: state,
		sendCh:              sendCh,
		sendDone:            sendDone,
	}
	testClient := &Client{
		connManager: newConnectionManager(),
		stopCh:      stopCh,
		stream:      stream,
	}
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		testClient.remoteToSendChannelWithFlowControl(connectID, eConn, make([]byte, agentToServerDataFrameSize))
	}()
	go testClient.sendChannelToProxy(connectID, eConn)

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			state.close()
			close(stopCh)
			select {
			case <-producerDone:
			case <-time.After(agentFlowControlTestSafetyTimeout):
				t.Error("response producer did not stop during queued-byte test cleanup")
			}
			close(sendCh)
			close(stream.sendRelease)
			select {
			case <-sendDone:
			case <-time.After(agentFlowControlTestSafetyTimeout):
				t.Error("response DATA sender did not stop during queued-byte test cleanup")
			}
			_ = endpoint.Close()
			_ = endpointPeer.Close()
		})
	}
	t.Cleanup(shutdown)

	receiveDataSend := func(stage string) []byte {
		select {
		case data := <-stream.dataSends:
			return data
		case <-time.After(agentFlowControlTestSafetyTimeout):
			t.Fatalf("response DATA sender did not attempt the %s payload", stage)
			return nil
		}
	}
	firstData := receiveDataSend("first non-empty")
	if !bytes.Equal(firstData, firstPayload) {
		t.Fatalf("first response DATA = %q, want %q after an empty successful endpoint Read", firstData, firstPayload)
	}
	select {
	case <-endpoint.allPayloadRead:
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("response producer did not read the payload that must be committed before queue publication")
	}
	waitForCommittedResponseBytes(t, state, uint64(grantedBytes))

	state.mu.Lock()
	sendLimit := state.sendLimit
	committedTotal := state.committedTotal
	sentTotal := state.sentTotal
	state.mu.Unlock()
	if sendLimit != uint64(grantedBytes) || committedTotal != uint64(grantedBytes) || sentTotal != 0 {
		t.Fatalf("state while payload publication is blocked by a full queue = {sendLimit: %d, committedTotal: %d, sentTotal: %d}, want %d, %d, 0", sendLimit, committedTotal, sentTotal, grantedBytes, grantedBytes)
	}
	if got := len(sendCh); got != 1 {
		t.Fatalf("queued response payloads while first DATA Send is blocked = %d, want 1", got)
	}

	stream.sendRelease <- struct{}{}
	secondData := receiveDataSend("queued")
	if !bytes.Equal(secondData, queuedPayload) {
		t.Fatalf("second response DATA = %q, want queued payload %q", secondData, queuedPayload)
	}
	waitForResponseFlowControlWait(t, state, endpoint.readBeyondPayload)
	state.mu.Lock()
	committedTotal = state.committedTotal
	sentTotal = state.sentTotal
	state.mu.Unlock()
	if committedTotal != uint64(grantedBytes) || sentTotal != uint64(len(firstPayload)) {
		t.Fatalf("state after blocked payload enters the queue = {committedTotal: %d, sentTotal: %d}, want %d, %d", committedTotal, sentTotal, grantedBytes, len(firstPayload))
	}
	if got := len(sendCh); got != 1 {
		t.Fatalf("queued response payloads while second DATA Send is blocked = %d, want 1", got)
	}
	wantReadSizes := []int{grantedBytes, grantedBytes, len(queuedPayload) + len(blockedPayload), len(blockedPayload)}
	if !slices.Equal(endpoint.readSizes, wantReadSizes) {
		t.Fatalf("endpoint Read sizes after empty successful Read = %v, want %v", endpoint.readSizes, wantReadSizes)
	}

	shutdown()
	if stream.dataSendCount != 3 {
		t.Fatalf("response DATA Sends after one empty and three non-empty Reads = %d, want 3", stream.dataSendCount)
	}
}

func TestHTTPConnectResponseFlowControlRequiresOffer(t *testing.T) {
	const (
		dialID   = int64(7102)
		target   = "legacy-flow-control-endpoint.invalid:443"
		protocol = "tcp"
	)
	payload := []byte("legacy response bytes")
	requestAfterIgnoredUpdate := []byte("legacy request after ignored WINDOW_UPDATE")

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

	requestRead := make(chan error, 1)
	readRequest := make([]byte, len(requestAfterIgnoredUpdate))
	go func() {
		_, err := io.ReadFull(peer, readRequest)
		requestRead <- err
	}()
	if err := serverStream.Send(newWindowUpdatePacket(dialResponse.GetConnectID(), uint64(len(payload)))); err != nil {
		t.Fatalf("send WINDOW_UPDATE for legacy connection: %v", err)
	}
	if err := serverStream.Send(newDataPacket(dialResponse.GetConnectID(), requestAfterIgnoredUpdate)); err != nil {
		t.Fatalf("send request DATA after ignored legacy WINDOW_UPDATE: %v", err)
	}
	select {
	case err := <-requestRead:
		if err != nil {
			t.Fatalf("read request after ignored legacy WINDOW_UPDATE: %v", err)
		}
		if !bytes.Equal(readRequest, requestAfterIgnoredUpdate) {
			t.Fatalf("legacy request after ignored WINDOW_UPDATE = %q, want %q", readRequest, requestAfterIgnoredUpdate)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("legacy request did not progress after ignored WINDOW_UPDATE")
	}

	eConn, ok := testClient.connManager.Get(dialResponse.GetConnectID())
	if !ok {
		t.Fatal("ignored legacy WINDOW_UPDATE removed the endpoint connection")
	}
	if eConn.responseFlowControl != nil {
		t.Fatal("legacy WINDOW_UPDATE installed response flow-control state")
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
		unknownConnectID = int64(7299)
		legacyConnectID  = int64(7203)
		firstConnectID   = int64(7201)
		secondConnectID  = int64(7202)
		ignoredLimit     = uint64(4093)
		firstLimit       = uint64(11)
		secondLimit      = uint64(7)
		maxFrameSize     = 1 << 12
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
			if state != nil {
				state.close()
			}
			testClient.connManager.Delete(connectID)
		}
		testClient.connManager.Add(connectID, endpoint)
	}
	addConnection(legacyConnectID, nil)
	addConnection(firstConnectID, firstState)
	addConnection(secondConnectID, secondState)

	serveDone := make(chan struct{})
	var servePanic any
	go func() {
		defer close(serveDone)
		defer func() {
			servePanic = recover()
		}()
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
			if servePanic != nil {
				t.Errorf("agent client panicked during WINDOW_UPDATE routing test: %v", servePanic)
			}
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

	// Serve processes stream packets serially, so each target update is an
	// ordered checkpoint proving the preceding ignored update was handled first.
	if err := serverStream.Send(newWindowUpdatePacket(unknownConnectID, ignoredLimit)); err != nil {
		t.Fatalf("send WINDOW_UPDATE for unknown connection: %v", err)
	}
	if err := serverStream.Send(newWindowUpdatePacket(firstConnectID, firstLimit)); err != nil {
		t.Fatalf("send first connection WINDOW_UPDATE: %v", err)
	}
	select {
	case result := <-firstAllowance:
		if !result.ok || result.size != int(firstLimit) {
			t.Fatalf("first connection allowance = %d, %t, want %d, true", result.size, result.ok, firstLimit)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("first connection did not wake for its WINDOW_UPDATE")
	case <-serveDone:
		if servePanic != nil {
			t.Fatalf("agent client panicked on WINDOW_UPDATE for unknown connection: %v", servePanic)
		}
		t.Fatal("agent client stopped on WINDOW_UPDATE for unknown connection")
	}
	if _, ok := testClient.connManager.Get(unknownConnectID); ok {
		t.Fatal("WINDOW_UPDATE created state for an unknown connection")
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

	if err := serverStream.Send(newWindowUpdatePacket(legacyConnectID, ignoredLimit)); err != nil {
		t.Fatalf("send WINDOW_UPDATE for legacy connection: %v", err)
	}
	if err := serverStream.Send(newWindowUpdatePacket(secondConnectID, secondLimit)); err != nil {
		t.Fatalf("send second connection WINDOW_UPDATE: %v", err)
	}
	select {
	case result := <-secondAllowance:
		if !result.ok || result.size != int(secondLimit) {
			t.Fatalf("second connection allowance = %d, %t, want %d, true", result.size, result.ok, secondLimit)
		}
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("second connection did not wake for its WINDOW_UPDATE")
	case <-serveDone:
		if servePanic != nil {
			t.Fatalf("agent client panicked on WINDOW_UPDATE for legacy connection: %v", servePanic)
		}
		t.Fatal("agent client stopped on WINDOW_UPDATE for legacy connection")
	}

	firstState.mu.Lock()
	firstSendLimit := firstState.sendLimit
	firstCommittedTotal := firstState.committedTotal
	firstState.mu.Unlock()
	if firstSendLimit != firstLimit || firstCommittedTotal != 0 {
		t.Fatalf("first connection state after legacy update = {sendLimit: %d, committedTotal: %d}, want %d, 0", firstSendLimit, firstCommittedTotal, firstLimit)
	}
}

type secondDataSendBlockingStream struct {
	agentproto.AgentService_ConnectClient

	dataSendCount     int
	secondSendStarted chan struct{}
	secondSendRelease <-chan struct{}
}

func (s *secondDataSendBlockingStream) Send(packet *client.Packet) error {
	if packet.GetType() == client.PacketType_DATA {
		s.dataSendCount++
		if s.dataSendCount == 2 {
			close(s.secondSendStarted)
			<-s.secondSendRelease
		}
	}
	return nil
}

func TestHTTPConnectResponseFlowControlRecordsSuccessfulDataSend(t *testing.T) {
	const (
		connectID       = int64(7301)
		remainingCredit = 9
		maxFrameSize    = 1 << 12
	)
	firstPayload := []byte("first committed response")
	secondPayload := []byte("second committed response")
	committedBytes := len(firstPayload) + len(secondPayload)

	state := newAgentToServerFlowControlState()
	t.Cleanup(state.close)
	state.advanceSendLimit(uint64(committedBytes + remainingCredit))
	if !state.commitRead(committedBytes) {
		t.Fatalf("commit response read of %d bytes was rejected", committedBytes)
	}

	secondSendStarted := make(chan struct{})
	secondSendRelease := make(chan struct{})
	var releaseSecondSend sync.Once
	releaseSecond := func() {
		releaseSecondSend.Do(func() {
			close(secondSendRelease)
		})
	}
	sendCh := make(chan []byte, 2)
	sendDone := make(chan struct{})
	t.Cleanup(func() {
		releaseSecond()
		select {
		case <-sendDone:
		case <-time.After(agentFlowControlTestSafetyTimeout):
			t.Error("response DATA sender did not finish during cleanup")
		}
	})
	eConn := &endpointConn{
		connID:              connectID,
		responseFlowControl: state,
		sendCh:              sendCh,
		sendDone:            sendDone,
	}
	stream := &secondDataSendBlockingStream{
		secondSendStarted: secondSendStarted,
		secondSendRelease: secondSendRelease,
	}
	testClient := &Client{stream: stream}
	sendCh <- firstPayload
	sendCh <- secondPayload
	close(sendCh)
	go testClient.sendChannelToProxy(connectID, eConn)

	select {
	case <-secondSendStarted:
	case <-sendDone:
		t.Fatal("response DATA sender finished before attempting the second send")
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("response DATA sender did not attempt the second send")
	}
	if got := stream.dataSendCount; got != 2 {
		t.Fatalf("DATA Send attempts before second send release = %d, want 2", got)
	}

	state.mu.Lock()
	sendLimit := state.sendLimit
	committedTotal := state.committedTotal
	sentTotal := state.sentTotal
	state.mu.Unlock()
	if want := uint64(len(firstPayload)); sentTotal != want {
		t.Fatalf("sent response bytes while second DATA Send is blocked = %d, want %d", sentTotal, want)
	}
	if want := uint64(committedBytes + remainingCredit); sendLimit != want || committedTotal != uint64(committedBytes) {
		t.Fatalf("state while second DATA Send is blocked = {sendLimit: %d, committedTotal: %d}, want %d, %d", sendLimit, committedTotal, want, committedBytes)
	}
	readSize, ok := state.nextReadSize(maxFrameSize)
	if !ok || readSize != remainingCredit {
		t.Fatalf("read allowance after first successful DATA Send = %d, %t, want %d, true", readSize, ok, remainingCredit)
	}

	releaseSecond()
	select {
	case <-sendDone:
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("response DATA sender did not finish")
	}
	if got := stream.dataSendCount; got != 2 {
		t.Fatalf("completed DATA Sends = %d, want 2", got)
	}

	state.mu.Lock()
	sendLimit = state.sendLimit
	committedTotal = state.committedTotal
	sentTotal = state.sentTotal
	state.mu.Unlock()
	if want := uint64(committedBytes); sentTotal != want {
		t.Fatalf("sent response bytes after both successful DATA Sends = %d, want %d", sentTotal, want)
	}
	if want := uint64(committedBytes + remainingCredit); sendLimit != want || committedTotal != uint64(committedBytes) {
		t.Fatalf("state after both successful DATA Sends = {sendLimit: %d, committedTotal: %d}, want %d, %d", sendLimit, committedTotal, want, committedBytes)
	}
}

func TestHTTPConnectResponseFlowControlRejectsInvalidSendProgress(t *testing.T) {
	for _, test := range []struct {
		name           string
		committedTotal uint64
		sentTotal      uint64
		bytes          int
	}{
		{
			name:           "one byte beyond committed",
			committedTotal: 8,
			sentTotal:      3,
			bytes:          6,
		},
		{
			name:           "negative byte count",
			committedTotal: ^uint64(0),
			bytes:          -1,
		},
		{
			name:           "corrupt existing progress",
			committedTotal: 7,
			sentTotal:      8,
			bytes:          1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newAgentToServerFlowControlState()
			state.sendLimit = test.committedTotal
			state.committedTotal = test.committedTotal
			state.sentTotal = test.sentTotal

			if state.recordSend(test.bytes) {
				t.Fatalf("recordSend(%d) = true, want false", test.bytes)
			}
			state.mu.Lock()
			committedTotal := state.committedTotal
			sentTotal := state.sentTotal
			state.mu.Unlock()
			if committedTotal != test.committedTotal || sentTotal != test.sentTotal {
				t.Fatalf("state after rejected send progress = {committedTotal: %d, sentTotal: %d}, want %d, %d", committedTotal, sentTotal, test.committedTotal, test.sentTotal)
			}
		})
	}
}

type responseDataSendFailureStream struct {
	agentproto.AgentService_ConnectClient

	failDataSend int
	dataSends    int
}

func (s *responseDataSendFailureStream) Send(packet *client.Packet) error {
	if packet.GetType() != client.PacketType_DATA {
		return nil
	}
	s.dataSends++
	if s.dataSends == s.failDataSend {
		return errors.New("injected response DATA Send failure")
	}
	return nil
}

func TestEndpointConnStartCleanupDoesNotWaitForSender(t *testing.T) {
	state := newAgentToServerFlowControlState()
	sendCh := make(chan []byte)
	sendDone := make(chan struct{})
	cleanupStarted := make(chan struct{})
	cleanupDone := make(chan struct{})
	eConn := &endpointConn{
		responseFlowControl: state,
		sendCh:              sendCh,
		sendDone:            sendDone,
	}
	eConn.cleanFunc = func() {
		close(sendCh)
		close(cleanupStarted)
		<-sendDone
		close(cleanupDone)
	}

	startReturned := make(chan struct{})
	go func() {
		eConn.startCleanup()
		close(startReturned)
	}()

	select {
	case <-cleanupStarted:
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("endpoint cleanup did not start")
	}
	select {
	case <-startReturned:
	case <-time.After(agentFlowControlTestSafetyTimeout):
		// Release a synchronous implementation before failing so the test does
		// not leave a permanently blocked sender-cleanup cycle behind.
		close(sendDone)
		<-startReturned
		t.Fatal("startCleanup waited for sender-owned sendDone")
	}

	state.mu.Lock()
	closed := state.closed
	state.mu.Unlock()
	if !closed {
		t.Fatal("startCleanup returned before closing response flow-control state")
	}
	close(sendDone)
	select {
	case <-cleanupDone:
	case <-time.After(agentFlowControlTestSafetyTimeout):
		t.Fatal("endpoint cleanup did not finish after sendDone closed")
	}
}

func TestHTTPConnectResponseFlowControlSendFailureIsTerminal(t *testing.T) {
	const (
		connectID    = int64(7401)
		maxFrameSize = 1 << 12
	)
	firstPayload := []byte("successfully sent response")
	failingPayload := []byte("ambiguous response DATA")
	backlogPayload := []byte("committed response backlog")

	for _, test := range []struct {
		name           string
		failDataSend   int
		committedTotal int
	}{
		{
			name:           "transport send error",
			failDataSend:   2,
			committedTotal: len(firstPayload) + len(failingPayload) + len(backlogPayload),
		},
		{
			name: "send progress rejection",
			// No injected transport error: the short committed total makes
			// the second successful Send fail recordSend instead.
			committedTotal: len(firstPayload) + len(failingPayload) - 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newAgentToServerFlowControlState()
			state.sendLimit = uint64(test.committedTotal)
			state.committedTotal = uint64(test.committedTotal)

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

			endpoint, peer := net.Pipe()
			manager := newConnectionManager()
			sendCh := make(chan []byte, 3)
			sendDone := make(chan struct{})
			cleanupDone := make(chan struct{})
			cleanupCalls := 0
			eConn := &endpointConn{
				conn:                endpoint,
				connID:              connectID,
				responseFlowControl: state,
				sendCh:              sendCh,
				sendDone:            sendDone,
			}
			eConn.cleanFunc = func() {
				cleanupCalls++
				state.close()
				manager.Delete(connectID)
				_ = endpoint.Close()
				close(cleanupDone)
			}
			manager.Add(connectID, eConn)
			t.Cleanup(func() {
				eConn.cleanup()
				_ = peer.Close()
			})

			stream := &responseDataSendFailureStream{failDataSend: test.failDataSend}
			testClient := &Client{
				connManager: manager,
				cs:          &ClientSet{clients: make(map[string]*Client)},
				stream:      stream,
			}
			sendCh <- firstPayload
			sendCh <- failingPayload
			sendCh <- backlogPayload
			close(sendCh)

			testClient.sendChannelToProxy(connectID, eConn)

			state.mu.Lock()
			closed := state.closed
			committedTotal := state.committedTotal
			sentTotal := state.sentTotal
			state.mu.Unlock()
			if !closed {
				t.Fatal("response flow-control state remained open after terminal DATA send failure")
			}
			if want := uint64(len(firstPayload)); sentTotal != want {
				t.Fatalf("sent response bytes after terminal DATA send failure = %d, want last valid total %d", sentTotal, want)
			}
			if committedTotal != uint64(test.committedTotal) {
				t.Fatalf("committed response bytes after terminal DATA send failure = %d, want unchanged %d", committedTotal, test.committedTotal)
			}
			if stream.dataSends != 2 {
				t.Fatalf("response DATA Send attempts after terminal failure = %d, want 2 with no backlog retry", stream.dataSends)
			}

			select {
			case result := <-nextAllowance:
				if result.ok || result.size != 0 {
					t.Fatalf("read allowance after terminal DATA send failure = %d, %t, want 0, false", result.size, result.ok)
				}
			case <-time.After(agentFlowControlTestSafetyTimeout):
				t.Fatal("terminal DATA send failure did not wake the response credit wait")
			}
			select {
			case <-cleanupDone:
			case <-time.After(agentFlowControlTestSafetyTimeout):
				t.Fatal("terminal DATA send failure did not clean up the endpoint connection")
			}
			if _, ok := manager.Get(connectID); ok {
				t.Fatal("terminal DATA send failure left the endpoint connection published")
			}
			if _, err := peer.Write([]byte("post-failure response")); err == nil {
				t.Fatal("endpoint socket remained writable after terminal DATA send failure")
			}
			eConn.cleanup()
			if cleanupCalls != 1 {
				t.Fatalf("endpoint cleanup calls after repeated cleanup = %d, want 1", cleanupCalls)
			}
		})
	}
}

func newWindowUpdatePacket(connectID int64, limit uint64) *client.Packet {
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

func waitForCommittedResponseBytes(t *testing.T, state *agentToServerFlowControlState, want uint64) {
	t.Helper()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(agentFlowControlTestSafetyTimeout)
	defer timeout.Stop()

	for {
		state.mu.Lock()
		committedTotal := state.committedTotal
		closed := state.closed
		state.mu.Unlock()
		if committedTotal == want {
			return
		}
		if committedTotal > want {
			t.Fatalf("response bytes committed before queue publication = %d, exceeded grant %d", committedTotal, want)
		}
		if closed {
			t.Fatalf("response flow-control state closed with %d committed bytes, want %d", committedTotal, want)
		}

		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("response bytes committed before queue publication = %d, want %d", committedTotal, want)
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

type dataAndEOFConn struct {
	net.Conn
	remaining []byte
	readSizes []int
}

func (c *dataAndEOFConn) Read(p []byte) (int, error) {
	c.readSizes = append(c.readSizes, len(p))
	n := copy(p, c.remaining)
	c.remaining = c.remaining[n:]
	if len(c.remaining) == 0 {
		return n, io.EOF
	}
	return n, nil
}

type zeroThenChunkedConn struct {
	net.Conn
	chunks            [][]byte
	emptyReadReturned bool
	readSizes         []int
	allPayloadRead    chan struct{}
	readBeyondPayload chan struct{}
}

func (c *zeroThenChunkedConn) Read(p []byte) (int, error) {
	c.readSizes = append(c.readSizes, len(p))
	if !c.emptyReadReturned {
		c.emptyReadReturned = true
		return 0, nil
	}
	if len(c.chunks) == 0 {
		close(c.readBeyondPayload)
		return 0, errors.New("endpoint Read exceeded granted response payload")
	}

	n := copy(p, c.chunks[0])
	if n == len(c.chunks[0]) {
		c.chunks = c.chunks[1:]
		if len(c.chunks) == 0 {
			close(c.allPayloadRead)
		}
	} else {
		c.chunks[0] = c.chunks[0][n:]
	}
	return n, nil
}

type observingDataSendBlockingStream struct {
	agentproto.AgentService_ConnectClient

	dataSendCount int
	dataSends     chan []byte
	sendRelease   chan struct{}
}

func (s *observingDataSendBlockingStream) Send(packet *client.Packet) error {
	if packet.GetType() == client.PacketType_DATA {
		s.dataSendCount++
		s.dataSends <- slices.Clone(packet.GetData().GetData())
		<-s.sendRelease
	}
	return nil
}
