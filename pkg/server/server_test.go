/*
Copyright 2019 The Kubernetes Authors.

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

package server_test

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"go.uber.org/goleak"
	"google.golang.org/grpc/metadata"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	fakeauthenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1/fake"
	k8stesting "k8s.io/client-go/testing"

	"sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/server"
	agentmock "sigs.k8s.io/apiserver-network-proxy/proto/agent/mocks"
	"sigs.k8s.io/apiserver-network-proxy/proto/header"
)

func TestAgentTokenAuthenticationErrorsToken(t *testing.T) {
	t.Skip()

	stub := gomock.NewController(t)
	defer stub.Finish()

	ns := "test_ns"
	sa := "test_sa"

	testCases := []struct {
		desc               string
		mdKey              string
		tokens             []string
		wantNamespace      string
		wantServiceAccount string
		authenticated      bool
		authError          string
		tokenReviewError   error
		wantError          bool
	}{
		{
			desc:      "no context",
			wantError: true,
		},
		{
			desc:      "non valid metadata key",
			mdKey:     "someKey",
			tokens:    []string{"token1"},
			wantError: true,
		},
		{
			desc:      "non valid token prefix",
			mdKey:     header.AuthenticationTokenContextKey,
			tokens:    []string{"token1"},
			wantError: true,
		},
		{
			desc:      "multiple valid tokens",
			mdKey:     header.AuthenticationTokenContextKey,
			tokens:    []string{header.AuthenticationTokenContextSchemePrefix + "token1", header.AuthenticationTokenContextSchemePrefix + "token2"},
			wantError: true,
		},
		{
			desc:               "not authenticated",
			authenticated:      false,
			mdKey:              header.AuthenticationTokenContextKey,
			tokens:             []string{header.AuthenticationTokenContextSchemePrefix + "token1"},
			wantNamespace:      ns,
			wantServiceAccount: sa,
			wantError:          true,
		},
		{
			desc:               "tokenReview error",
			authenticated:      false,
			mdKey:              header.AuthenticationTokenContextKey,
			tokens:             []string{header.AuthenticationTokenContextSchemePrefix + "token1"},
			tokenReviewError:   fmt.Errorf("some error"),
			wantNamespace:      ns,
			wantServiceAccount: sa,
			wantError:          true,
		},
		{
			desc:               "non valid namespace",
			authenticated:      true,
			mdKey:              header.AuthenticationTokenContextKey,
			tokens:             []string{header.AuthenticationTokenContextSchemePrefix + "token1"},
			wantNamespace:      "_" + ns,
			wantServiceAccount: sa,
			wantError:          true,
		},
		{
			desc:               "non valid service account",
			authenticated:      true,
			mdKey:              header.AuthenticationTokenContextKey,
			tokens:             []string{header.AuthenticationTokenContextSchemePrefix + "token1"},
			wantNamespace:      ns,
			wantServiceAccount: "_" + sa,
			wantError:          true,
		},
		{
			desc:               "authorization succeed",
			authenticated:      true,
			mdKey:              header.AuthenticationTokenContextKey,
			tokens:             []string{header.AuthenticationTokenContextSchemePrefix + "token1"},
			wantNamespace:      ns,
			wantServiceAccount: sa,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			kcs := k8sfake.NewSimpleClientset()

			kcs.AuthenticationV1().(*fakeauthenticationv1.FakeAuthenticationV1).Fake.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				tr := &authv1.TokenReview{
					Status: authv1.TokenReviewStatus{
						Authenticated: tc.authenticated,
						Error:         tc.authError,
						User: authv1.UserInfo{
							Username: fmt.Sprintf("system:serviceaccount:%v:%v", ns, sa),
						},
					},
				}
				return true, tr, tc.tokenReviewError
			})

			var md metadata.MD
			for _, token := range tc.tokens {
				md = metadata.Join(md, metadata.Pairs(tc.mdKey, token))
			}

			md = metadata.Join(md, metadata.Pairs(header.AgentID, ""))

			ctx := context.Background()
			defer ctx.Done()
			ctx = metadata.NewIncomingContext(ctx, md)
			conn := agentmock.NewMockAgentService_ConnectServer(stub)
			conn.EXPECT().Context().AnyTimes().Return(ctx)

			// close agent's connection if no error is expected
			if !tc.wantError {
				conn.EXPECT().SendHeader(gomock.Any()).Return(nil)
				conn.EXPECT().Recv().Return(nil, io.EOF)
			}

			p := server.NewProxyServer("", []server.ProxyStrategy{server.ProxyStrategyDefault}, 1, &server.AgentTokenAuthenticationOptions{
				Enabled:             true,
				KubernetesClient:    kcs,
				AgentNamespace:      tc.wantNamespace,
				AgentServiceAccount: tc.wantServiceAccount,
			},
				false,
			)

			err := p.Connect(conn)
			if tc.wantError {
				if err == nil {
					t.Errorf("test case expected for error")
				}
			} else {
				if err != nil {
					t.Errorf("did not expected for error but got :%v", err)
				}
			}
		})
	}
}

type mockStream struct {
	receive chan *client.Packet
	t       *testing.T
	send    chan *client.Packet
}

func (c *mockStream) Context() context.Context {
	return metadata.NewIncomingContext(context.TODO(), metadata.MD{
		header.AgentID:          []string{"1"},
		header.AgentIdentifiers: []string{"ipv4=1.1.1.1"},
	})
}

func (c *mockStream) Recv() (*client.Packet, error) {
	if packet := <-c.receive; packet != nil {
		return packet, nil
	}

	return nil, io.EOF
}

func (c *mockStream) Send(p *client.Packet) error {
	c.send <- p

	return nil
}

func (c *mockStream) SendHeader(h metadata.MD) error {
	c.t.Logf("Sending header: %v", h)

	return nil
}

func Test_NewProxyServer(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("k8s.io/klog/v2.(*loggingT).flushDaemon"))

	done := make(chan error)

	go func() {
		testProxyServer := server.NewProxyServer("foo", []server.ProxyStrategy{server.ProxyStrategyDefault}, 1, &server.AgentTokenAuthenticationOptions{}, false)

		agentSends := make(chan *client.Packet)
		agentDone := make(chan error)
		agentReceives := make(chan *client.Packet)

		var wg sync.WaitGroup

		go func() {
			t.Log("Agent started")

			// Connect registers backend in the proxy server.
			agentDone <- testProxyServer.Connect(&mockStream{
				receive: agentSends,
				t:       t,
				send:    agentReceives,
			})

			t.Log("Agent exited")
		}()

		proxyClientSends := make(chan *client.Packet)
		proxyClientDone := make(chan error)
		proxyClientReceives := make(chan *client.Packet)

		// Requesting proxy connection to 1.1.1.1.
		//
		// This request will be forwarded to the backend.
		func() {
			agentResponded := false

			for {
				if !agentResponded {
					// If proxy responds with no backend error, connection proxy will be closed, so we need to start it again.
					go func() {
						t.Log("Proxy started")
						wg.Add(1)

						proxyClientDone <- testProxyServer.Proxy(&mockStream{
							receive: proxyClientSends,
							t:       t,
							send:    proxyClientReceives,
						})

						t.Log("Proxy exited")
						wg.Done()
					}()

					t.Log("Sending dial request")

					proxyClientSends <- &client.Packet{
						Type: client.PacketType_DIAL_REQ,
						Payload: &client.Packet_DialRequest{
							DialRequest: &client.DialRequest{
								Address: "1.1.1.1",
								Random:  1,
							},
						},
					}
				}

				t.Log("Waiting for proxy server to respond")

				select {
				case <-agentReceives:
					t.Log("Backend registered, responding with agent response")
					// For dial request, proxy responds with dial response.
					agentSends <- &client.Packet{
						Type: client.PacketType_DIAL_RSP,
						Payload: &client.Packet_DialResponse{
							DialResponse: &client.DialResponse{
								Random: 1,
							},
						},
					}

					agentResponded = true
				case response := <-proxyClientReceives:
					t.Log("Proxy client received response from proxy server, inspecting...")

					err := response.GetDialResponse().Error
					if err == "" {
						t.Log("Connected to the backend!")
						return
					}

					t.Logf("Got dial error %q, retrying", err)
					t.Log("Terminating existing proxy stream")
					// TODO: Client must send io.EOF over stream in case of no backend error?
					// Otherwise receiving loop exits, but Recv will keep pushing data.
					proxyClientSends <- nil
				}
			}
		}()

		t.Log("Closing proxy client connection")

		proxyClientSends <- nil

		t.Logf("Agent received: %v", <-agentReceives)

		t.Log("Waiting for all started proxy clients to exit")

		go func() {
			wg.Add(1)

			for err := range proxyClientDone {
				if err != nil {
					t.Fatalf("Unexpected error from proxy: %v", err)
				}
			}

			wg.Done()
		}()

		t.Log("Proxy client exited")

		agentSends <- nil

		t.Log("Waiting for agent to exit")

		if err := <-agentDone; err != nil {
			t.Fatalf("Got unexpected error while connecting: %v", err)
		}

		t.Logf("Proxy client receives after exiting!: %v", <-proxyClientReceives)

		close(proxyClientReceives)
		close(agentReceives)

		close(proxyClientDone)

		t.Log("Waiting for all goroutines to exit")

		wg.Wait()

		for f := range proxyClientReceives {
			t.Fatalf("Unexpected message received by proxy client after exiting: %v", f)
		}
		for f := range agentReceives {
			t.Fatalf("Unexpected message received by agent after exiting: %v", f)
		}

		done <- nil
	}()

	timeout := time.NewTimer(30 * time.Second)

	select {
	case <-done:
	case <-timeout.C:
		t.Log("timeout")
	}
}

/*
func TestAddRemoveFrontends(t *testing.T) {
	agent1ConnID1 := new(server.ProxyClientConnection)
	agent1ConnID2 := new(server.ProxyClientConnection)
	agent2ConnID1 := new(server.ProxyClientConnection)
	agent2ConnID2 := new(server.ProxyClientConnection)
	agent3ConnID1 := new(server.ProxyClientConnection)

	p := server.NewProxyServer("", []server.ProxyStrategy{server.ProxyStrategyDefault}, 1, nil, false)
	p.addFrontend("agent1", int64(1), agent1ConnID1)
	p.removeFrontend("agent1", int64(1))
	expectedFrontends := make(map[string]map[int64]*server.ProxyClientConnection)
	if e, a := expectedFrontends, p.frontends; !reflect.DeepEqual(e, a) {
		t.Errorf("expected %v, got %v", e, a)
	}

	p = server.NewProxyServer("", []server.ProxyStrategy{server.ProxyStrategyDefault}, 1, nil, false)
	p.addFrontend("agent1", int64(1), agent1ConnID1)
	p.addFrontend("agent1", int64(2), agent1ConnID2)
	p.addFrontend("agent2", int64(1), agent2ConnID1)
	p.addFrontend("agent2", int64(2), agent2ConnID2)
	p.addFrontend("agent3", int64(1), agent3ConnID1)
	p.removeFrontend("agent2", int64(1))
	p.removeFrontend("agent2", int64(2))
	p.removeFrontend("agent1", int64(1))
	expectedFrontends = map[string]map[int64]*server.ProxyClientConnection{
		"agent1": {
			int64(2): agent1ConnID2,
		},
		"agent3": {
			int64(1): agent3ConnID1,
		},
	}
	if e, a := expectedFrontends, p.frontends; !reflect.DeepEqual(e, a) {
		t.Errorf("expected %v, got %v", e, a)
	}
}*/
