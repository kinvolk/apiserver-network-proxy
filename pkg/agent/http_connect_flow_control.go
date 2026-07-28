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

import "sync"

type agentToServerFlowControlState struct {
	mu sync.Mutex

	changed *sync.Cond

	sendLimit      uint64
	committedTotal uint64
	closed         bool
	// waiting exposes credit-wait entry to tests; protocol behavior does not
	// depend on it.
	waiting bool
}
