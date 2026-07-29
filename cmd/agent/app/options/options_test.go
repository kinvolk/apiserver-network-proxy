/*
Copyright 2022 The Kubernetes Authors.

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

package options

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

/*
 * TestDefaultServerOptions is intended to ensure we do not make a backward incompatible
 * change to the default flag values for the ANP agent.
 */
func TestDefaultServerOptions(t *testing.T) {
	defaultAgentOptions := NewGrpcProxyAgentOptions()
	assertDefaultValue(t, "AgentCert", defaultAgentOptions.AgentCert, "")
	assertDefaultValue(t, "AgentKey", defaultAgentOptions.AgentKey, "")
	assertDefaultValue(t, "CaCert", defaultAgentOptions.CaCert, "")
	assertDefaultValue(t, "ProxyServerHost", defaultAgentOptions.ProxyServerHost, "127.0.0.1")
	assertDefaultValue(t, "ProxyServerPort", defaultAgentOptions.ProxyServerPort, 8091)
	assertDefaultValue(t, "HealthServerHost", defaultAgentOptions.HealthServerHost, "")
	assertDefaultValue(t, "HealthServerPort", defaultAgentOptions.HealthServerPort, 8093)
	assertDefaultValue(t, "AdminBindAddress", defaultAgentOptions.AdminBindAddress, "127.0.0.1")
	assertDefaultValue(t, "AdminServerPort", defaultAgentOptions.AdminServerPort, 8094)
	assertDefaultValue(t, "EnableProfiling", defaultAgentOptions.EnableProfiling, false)
	assertDefaultValue(t, "EnableContentionProfiling", defaultAgentOptions.EnableContentionProfiling, false)
	assertDefaultValue(t, "AgentIdentifiers", defaultAgentOptions.AgentIdentifiers, "")
	assertDefaultValue(t, "SyncInterval", defaultAgentOptions.SyncInterval, 1*time.Second)
	assertDefaultValue(t, "ProbeInterval", defaultAgentOptions.ProbeInterval, 1*time.Second)
	assertDefaultValue(t, "SyncIntervalCap", defaultAgentOptions.SyncIntervalCap, 10*time.Second)
	assertDefaultValue(t, "KeepaliveTime", defaultAgentOptions.KeepaliveTime, 1*time.Hour)
	assertDefaultValue(t, "ServiceAccountTokenPath", defaultAgentOptions.ServiceAccountTokenPath, "")
	assertDefaultValue(t, "WarnOnChannelLimit", defaultAgentOptions.WarnOnChannelLimit, false)
	assertDefaultValue(t, "SyncForever", defaultAgentOptions.SyncForever, false)
	assertDefaultValue(t, "XfrChannelSize", defaultAgentOptions.XfrChannelSize, 150)
	assertDefaultValue(t, "APIContentType", defaultAgentOptions.APIContentType, "application/vnd.kubernetes.protobuf")
}

func TestAgentServerDataFlowControlFlag(t *testing.T) {
	const (
		name      = "enable-agent-server-data-flow-control"
		oldName   = "enable-http-connect-flow-control"
		wantUsage = "Enable negotiated flow control for DATA exchanged between the agent and proxy servers. Currently applies only to agent-to-server DATA; server-to-agent DATA remains legacy."
	)

	flags := NewGrpcProxyAgentOptions().Flags()
	flag := flags.Lookup(name)
	if flag == nil {
		t.Fatalf("agent flag %q is not registered", name)
	}
	if got, want := flag.DefValue, "false"; got != want {
		t.Fatalf("agent flag %q default = %q, want %q", name, got, want)
	}
	if got := flag.Usage; got != wantUsage {
		t.Fatalf("agent flag %q usage = %q, want %q", name, got, wantUsage)
	}
	if err := flags.Set(name, "true"); err != nil {
		t.Fatalf("set agent flag %q: %v", name, err)
	}
	if got, want := flag.Value.String(), "true"; got != want {
		t.Fatalf("agent flag %q value = %q, want %q", name, got, want)
	}
	if oldFlag := flags.Lookup(oldName); oldFlag != nil {
		t.Fatalf("agent frontend-specific flag %q remains registered", oldName)
	}
}

func TestAgentServerDataFlowControlPolicyReachesClientSetConfig(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := NewGrpcProxyAgentOptions()
			options.EnableAgentServerDataFlowControl = tt.enabled
			config := options.ClientSetConfig()

			options.EnableAgentServerDataFlowControl = !tt.enabled
			if got := config.EnableAgentServerDataFlowControl; got != tt.enabled {
				t.Fatalf("client-set config agent-server DATA flow-control policy = %t, want snapshotted %t from agent options", got, tt.enabled)
			}
		})
	}
}

func assertDefaultValue(t *testing.T, fieldName string, actual, expected interface{}) {
	t.Helper()
	assert.IsType(t, expected, actual, "For field %s, got the wrong type.", fieldName)
	assert.Equal(t, expected, actual, "For field %s, got the wrong value.", fieldName)
}

func TestValidate(t *testing.T) {
	for desc, tc := range map[string]struct {
		fieldMap map[string]interface{}
		expected error
	}{
		"default": {
			fieldMap: map[string]interface{}{},
			expected: nil,
		},
		"ZeroProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": 0},
			expected: fmt.Errorf("proxy server port 0 must be greater than 0"),
		},
		"NegativeProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": -1},
			expected: fmt.Errorf("proxy server port -1 must be greater than 0"),
		},
		"ReservedProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": 1023},
			expected: nil, //TODO: fmt.Errorf("please do not try to use reserved port 1023 for the proxy server port"),
		},
		"StartValidProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": 1024},
			expected: nil,
		},
		"EndValidProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": 49151},
			expected: nil,
		},
		"StartEphemeralProxyServerPort": {
			fieldMap: map[string]interface{}{"ProxyServerPort": 49152},
			expected: nil, //TODO: fmt.Errorf("please do not try to use ephemeral port 49152 for the proxy server port"),
		},
		"ZeroHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": 0},
			expected: fmt.Errorf("health server port 0 must be greater than 0"),
		},
		"NegativeHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": -1},
			expected: fmt.Errorf("health server port -1 must be greater than 0"),
		},
		"ReservedHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": 1023},
			expected: nil, //TODO: fmt.Errorf("please do not try to use reserved port 1023 for the health server port"),
		},
		"StartValidHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": 1024},
			expected: nil,
		},
		"EndValidHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": 49151},
			expected: nil,
		},
		"StartEphemeralHealthServerPort": {
			fieldMap: map[string]interface{}{"HealthServerPort": 49152},
			expected: nil, //TODO: fmt.Errorf("please do not try to use ephemeral port 49152 for the health server port"),
		},
		"ZeroAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": 0},
			expected: fmt.Errorf("admin server port 0 must be greater than 0"),
		},
		"NegativeAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": -1},
			expected: fmt.Errorf("admin server port -1 must be greater than 0"),
		},
		"ReservedAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": 1023},
			expected: nil, //TODO: fmt.Errorf("please do not try to use reserved port 1023 for the health port"),
		},
		"StartValidAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": 1024},
			expected: nil,
		},
		"EndValidAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": 49151},
			expected: nil,
		},
		"StartEphemeralAdminServerPort": {
			fieldMap: map[string]interface{}{"AdminServerPort": 49152},
			expected: nil, //TODO: fmt.Errorf("please do not try to use ephemeral port 49152 for the health port"),
		},
		"ContentionProfilingRequiresProfiling": {
			fieldMap: map[string]interface{}{
				"EnableContentionProfiling": true,
				"EnableProfiling":           false,
			},
			expected: fmt.Errorf("if --enable-contention-profiling is set, --enable-profiling must also be set"),
		},
		"ZeroXfrChannelSize": {
			fieldMap: map[string]interface{}{"XfrChannelSize": 0},
			expected: fmt.Errorf("channel size 0 must be greater than 0"),
		},
		"NegativeXfrChannelSize": {
			fieldMap: map[string]interface{}{"XfrChannelSize": -10},
			expected: fmt.Errorf("channel size -10 must be greater than 0"),
		},
		"ServerCountSource": {
			fieldMap: map[string]interface{}{"ServerCountSource": "foobar"},
			expected: fmt.Errorf("--server-count-source must be one of '', 'default', 'max', got foobar"),
		},
	} {
		t.Run(desc, func(t *testing.T) {
			testAgentOptions := NewGrpcProxyAgentOptions()
			for field, value := range tc.fieldMap {
				rv := reflect.ValueOf(testAgentOptions)
				rv = rv.Elem()
				fv := rv.FieldByName(field)
				switch reflect.TypeOf(value).Kind() {
				case reflect.String:
					svalue := value.(string)
					fv.SetString(svalue)
				case reflect.Int:
					ivalue := value.(int)
					fv.SetInt(int64(ivalue))
				case reflect.Bool:
					bvalue := value.(bool)
					fv.SetBool(bvalue)
				}
			}
			actual := testAgentOptions.Validate()
			assert.IsType(t, tc.expected, actual, "Validation for case %s, got the wrong type.", desc)
			assert.Equal(t, tc.expected, actual, "Validation for case %s, got the wrong value.", desc)
		})
	}
}
