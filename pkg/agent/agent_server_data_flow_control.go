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
	"sync"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
)

type agentToServerFlowControlState struct {
	mu sync.Mutex

	changed *sync.Cond

	sendLimit      uint64
	committedTotal uint64
	sentTotal      uint64
	closed         bool
	// waiting exposes credit-wait entry to tests; protocol behavior does not
	// depend on it.
	waiting bool
}

func offeredAgentToServerFlowControlV1(features []client.FlowControlFeature) bool {
	for _, feature := range features {
		if feature == client.FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1 {
			return true
		}
	}
	return false
}

func newAgentToServerFlowControlState() *agentToServerFlowControlState {
	state := &agentToServerFlowControlState{}
	state.changed = sync.NewCond(&state.mu)
	return state
}

func (s *agentToServerFlowControlState) advanceSendLimit(maxDataOffset uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || maxDataOffset <= s.sendLimit {
		return
	}
	s.sendLimit = maxDataOffset
	s.changed.Broadcast()
}

func (s *agentToServerFlowControlState) nextReadSize(maxFrameSize int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for !s.closed && s.committedTotal == s.sendLimit {
		s.waiting = true
		s.changed.Wait()
		s.waiting = false
	}
	if s.closed {
		return 0, false
	}

	allowance := s.sendLimit - s.committedTotal
	if allowance > uint64(maxFrameSize) {
		return maxFrameSize, true
	}
	return int(allowance), true
}

func (s *agentToServerFlowControlState) commitRead(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate before unsigned arithmetic so invalid input or corrupt state
	// cannot manufacture allowance through conversion or subtraction underflow.
	if n < 0 || s.committedTotal > s.sendLimit {
		return false
	}
	amount := uint64(n)
	if amount > s.sendLimit-s.committedTotal {
		return false
	}
	s.committedTotal += amount
	return true
}

func (s *agentToServerFlowControlState) recordSend(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate before unsigned arithmetic so invalid input or corrupt state
	// cannot manufacture send progress through conversion or subtraction underflow.
	if n < 0 || s.sentTotal > s.committedTotal {
		return false
	}
	amount := uint64(n)
	if amount > s.committedTotal-s.sentTotal {
		return false
	}
	s.sentTotal += amount
	return true
}

func (s *agentToServerFlowControlState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true
	s.changed.Broadcast()
}
