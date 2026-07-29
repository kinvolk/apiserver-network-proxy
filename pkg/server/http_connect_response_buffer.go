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

// httpConnectResponseBuffer is an inert compile seam for the response-buffer
// contract. The implementation follows in the production commit.
type httpConnectResponseBuffer struct{}

func newHTTPConnectResponseBuffer(int64) *httpConnectResponseBuffer {
	return &httpConnectResponseBuffer{}
}

func (*httpConnectResponseBuffer) enqueue([]byte) bool {
	return false
}

func (*httpConnectResponseBuffer) peek() ([]byte, <-chan struct{}, bool) {
	return nil, nil, false
}

func (*httpConnectResponseBuffer) consume(int) bool {
	return false
}

func (*httpConnectResponseBuffer) capacity() int64 {
	return 0
}

func (*httpConnectResponseBuffer) bufferedBytes() int64 {
	return 0
}

func (*httpConnectResponseBuffer) close() {}
