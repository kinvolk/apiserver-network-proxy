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

package client

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestResponseFlowControlSchema(t *testing.T) {
	if got, want := PacketType_WINDOW_UPDATE, PacketType(7); got != want {
		t.Fatalf("WINDOW_UPDATE value = %d, want %d", got, want)
	}
	if got, want := FlowControlFeature_AGENT_TO_SERVER_BYTE_WINDOW_V1, FlowControlFeature(1); got != want {
		t.Fatalf("AGENT_TO_SERVER_BYTE_WINDOW_V1 value = %d, want %d", got, want)
	}

	fields := []struct {
		name       string
		descriptor protoreflect.MessageDescriptor
		field      protoreflect.Name
		number     protoreflect.FieldNumber
	}{
		{
			name:       "dial request offer",
			descriptor: (&DialRequest{}).ProtoReflect().Descriptor(),
			field:      "offered_flow_control_features",
			number:     4,
		},
		{
			name:       "dial response acceptance",
			descriptor: (&DialResponse{}).ProtoReflect().Descriptor(),
			field:      "accepted_flow_control_features",
			number:     4,
		},
		{
			name:       "packet window update",
			descriptor: (&Packet{}).ProtoReflect().Descriptor(),
			field:      "window_update",
			number:     9,
		},
		{
			name:       "window update connection",
			descriptor: (&WindowUpdate{}).ProtoReflect().Descriptor(),
			field:      "connect_id",
			number:     1,
		},
		{
			name:       "window update limit",
			descriptor: (&WindowUpdate{}).ProtoReflect().Descriptor(),
			field:      "max_data_offset",
			number:     2,
		},
	}
	for _, test := range fields {
		t.Run(test.name, func(t *testing.T) {
			field := test.descriptor.Fields().ByName(test.field)
			if field == nil {
				t.Fatalf("field %q not found", test.field)
			}
			if got := field.Number(); got != test.number {
				t.Fatalf("field %q number = %d, want %d", test.field, got, test.number)
			}
		})
	}

	want := &Packet{
		Type: PacketType_WINDOW_UPDATE,
		Payload: &Packet_WindowUpdate{
			WindowUpdate: &WindowUpdate{
				ConnectId:     42,
				MaxDataOffset: 64 << 10,
			},
		},
	}
	wire, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("marshal WINDOW_UPDATE: %v", err)
	}
	got := new(Packet)
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("unmarshal WINDOW_UPDATE: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("WINDOW_UPDATE round trip = %v, want %v", got, want)
	}
}
