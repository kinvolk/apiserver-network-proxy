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

package app

import (
	"reflect"
	"testing"
	"time"

	"sigs.k8s.io/apiserver-network-proxy/cmd/server/app/options"
)

func TestLogHTTPConnectFlowControlConfig(t *testing.T) {
	testCases := []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := options.NewProxyRunOptions()
			o.EnableHTTPConnectFlowControl = tc.enabled
			o.HTTPConnectFlowControlWindowSize = 64 << 10
			o.HTTPConnectFlowControlPoolSize = 100 << 10
			o.HTTPConnectFlowControlMaxPendingAdmissions = 17
			o.HTTPConnectFlowControlAdmissionTimeout = 750 * time.Millisecond

			var (
				calls            int
				gotMessage       string
				gotKeysAndValues []interface{}
			)
			logHTTPConnectFlowControlConfig(func(message string, keysAndValues ...interface{}) {
				calls++
				gotMessage = message
				gotKeysAndValues = append([]interface{}(nil), keysAndValues...)
			}, o)

			if calls != 1 {
				t.Fatalf("startup capacity summary calls = %d, want 1", calls)
			}
			if want := "Configured HTTP CONNECT response flow control"; gotMessage != want {
				t.Errorf("startup capacity summary message = %q, want %q", gotMessage, want)
			}
			// Keep the reservation count as int64 so byte-derived capacity is
			// not narrowed before it reaches structured logging.
			wantKeysAndValues := []interface{}{
				"windowSizeBytes", int64(64 << 10),
				"poolSizeBytes", int64(100 << 10),
				"maxReservations", int64(1),
				"maxPendingAdmissions", 17,
				"admissionTimeout", 750 * time.Millisecond,
			}
			if !reflect.DeepEqual(gotKeysAndValues, wantKeysAndValues) {
				t.Errorf("startup capacity summary values = %#v, want %#v", gotKeysAndValues, wantKeysAndValues)
			}
		})
	}
}
