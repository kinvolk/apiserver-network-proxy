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
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server/metrics"
)

func TestFrontendWriteLatencyExcludesHTTPPacketRoutingErrors(t *testing.T) {
	metrics.Metrics.Reset()
	t.Cleanup(metrics.Metrics.Reset)

	connection := &ProxyClientConnection{Mode: ModeHTTPConnect}
	if err := connection.send(&client.Packet{Type: client.PacketType_DATA}); err == nil {
		t.Fatal("HTTP packet routing through send unexpectedly succeeded")
	}
	if got := frontendWriteLatencySampleCount(t); got != 0 {
		t.Fatalf("frontend write latency samples after HTTP routing error = %d, want 0", got)
	}

	var frontend bytes.Buffer
	writer := newHTTPConnectWriter(nil, &ProxyClientConnection{
		Mode: ModeHTTPConnect,
		HTTP: &frontend,
	}, nil, false)
	if err := writer.write([]byte("frontend bytes")); err != nil {
		t.Fatalf("HTTP frontend write: %v", err)
	}
	if got := frontendWriteLatencySampleCount(t); got != 1 {
		t.Fatalf("frontend write latency samples after HTTP socket write = %d, want 1", got)
	}
}

func frontendWriteLatencySampleCount(t *testing.T) uint64 {
	t.Helper()
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	const metricName = "konnectivity_network_proxy_server_frontend_write_duration_seconds"
	var count uint64
	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}
		for _, metric := range family.GetMetric() {
			histogram := metric.GetHistogram()
			if histogram == nil {
				t.Fatalf("metric %s is not a histogram", metricName)
			}
			count += histogram.GetSampleCount()
		}
	}
	return count
}
