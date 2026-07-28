# HTTP-CONNECT Response Flow Control

## Problem

The proxy server multiplexes packets from one agent connection through a
shared receive loop. For HTTP-CONNECT traffic, response DATA eventually reaches
the client through this path:

~~~text
endpoint -> agent -> konnectivity-server -> HTTP-CONNECT client
~~~

If writing response DATA for connection A blocks on its HTTP socket, the shared
receive loop cannot process later packets for connection B. A slow or stalled
HTTP client can therefore delay unrelated DATA, dial responses, and close
packets on the same agent stream.

Moving the socket write to a per-connection worker is necessary but not
sufficient. Without producer-side flow control, a finite per-connection DATA
queue eventually fills and must either discard DATA or terminate a connection
that may still be healthy. An unbounded queue converts the same condition into
unbounded memory growth.

The required behavior is:

- A blocked connection stops producing response DATA before its reserved
  receive capacity is exhausted.
- It remains open at zero available capacity.
- Other negotiated connections continue to make progress.
- Memory remains bounded independently of how long the client stays blocked or
  how much DATA the endpoint attempts to produce.
- A temporarily blocked connection resumes without loss, duplication, or
  reordering.

## Scope and guarantees

This design adds flow control for the response direction:

~~~text
endpoint -> agent -> server -> HTTP-CONNECT client
             DATA ----->
                  <----- WINDOW_UPDATE
~~~

In scope:

- Additive per-dial feature negotiation.
- A cumulative byte window for agent-to-server DATA.
- Agent endpoint-read gating.
- A process-wide server reservation pool.
- A bounded pre-HTTP-200 admission queue.
- A reservation-backed per-connection byte buffer.
- One HTTP socket writer per negotiated connection.
- HTTP 200, DATA, close, and error ordering.
- Compatibility with peers that do not implement response flow control.
- Tests, metrics, configuration, and rollout requirements.

Out of scope:

- Flow control for client-to-server-to-agent request DATA.
- Changing the kube-apiserver HTTP-CONNECT interface.
- Replacing the multiplexed agent-server connection with per-connection gRPC
  streams.
- Changing the behavior of non-negotiated legacy DATA.
- Guaranteeing progress when the unchanged request path blocks delivery of a
  WINDOW_UPDATE on the shared agent receive loop.

Compatibility and safety are separate guarantees. Pre-feature peers continue
to establish, transfer DATA in both directions, and close using the legacy
protocol. Response flow-control safety applies only when both peers positively
negotiate AGENT_TO_SERVER_BYTE_WINDOW_V1 for the dial.

## Solution overview

The server grants each negotiated connection a cumulative maximum DATA offset.
The agent must not read endpoint bytes that would make its committed byte total
exceed that limit. The server advances the limit only after the HTTP socket
accepts response bytes.

Each admitted connection reserves a fixed receive window W from a process-wide
pool. Response V1 uses a configurable 64 KiB window by default. Every byte the
server authorizes but the HTTP socket has not yet consumed is therefore backed
by reserved capacity before the agent is allowed to read it.

When the HTTP client stops reading:

1. The connection-owned HTTP writer stops consuming its byte buffer.
2. The server stops advancing the cumulative limit.
3. The agent consumes its remaining credit and reaches zero.
4. The agent stops reading that endpoint socket.
5. TCP backpressure propagates to the endpoint.

Zero available credit is a normal state. It does not close the connection,
grow a DATA queue, or start a slow-reader timeout.

The connection establishment sequence is:

~~~text
HTTP client sends CONNECT
        |
server sends DIAL_REQ with response V1 offered
        |
agent attempts endpoint dial
        |
failed dial -> unsuccessful DIAL_RSP, no flow state or reservation
        |
successful dial -> agent installs zero-credit state
        |
agent sends successful DIAL_RSP with response V1 accepted
        |
server reserves W immediately or enters bounded pre-200 admission
        +-- queue disabled/full or admission timeout
        |       -> attempt complete HTTP 503 through the sole writer,
        |          close endpoint, and never write HTTP 200
        |
        `-- reservation available
                    |
                    v
        install byte buffer, counters, terminal state, and sole HTTP writer
                    |
        write the complete HTTP 200 response
                    |
        HTTP client enters tunnel mode
                    |
        server sends the initial WINDOW_UPDATE with limit W
~~~

A successful legacy DIAL_RSP bypasses the allocator and admission queue. A
failed DIAL_RSP creates no flow-control state. No byte of HTTP 200 is written
while a negotiated dial is waiting for admission.

If the agent is delayed after sending a successful DIAL_RSP, it produces no
response DATA until it processes positive credit and schedules an endpoint
Read. Published credit remains reserved because the agent may legally consume
it later. The server must not wait for the first endpoint Read or response DATA
before writing HTTP 200: an endpoint may wait for a request that the HTTP client
sends only after receiving 200.

## Flow-control protocol

### Additive schema

Use the next unused upstream field and enum values:

~~~proto
enum FlowControlFeature {
  FLOW_CONTROL_FEATURE_UNSPECIFIED = 0;
  AGENT_TO_SERVER_BYTE_WINDOW_V1 = 1;
}

message DialRequest {
  // Existing fields remain unchanged.
  repeated FlowControlFeature offered_flow_control_features = 4;
}

message DialResponse {
  // Existing fields remain unchanged.
  repeated FlowControlFeature accepted_flow_control_features = 4;
}

enum PacketType {
  // Existing values remain unchanged.
  WINDOW_UPDATE = 7;
}

message Packet {
  // Existing payload fields remain unchanged.
  oneof payload {
    WindowUpdate window_update = 9;
  }
}

message WindowUpdate {
  int64 connect_id = 1;
  uint64 max_data_offset = 2;
}
~~~

No field is added to DATA. WINDOW_UPDATE authorizes DATA travelling in the
opposite direction:

- Server to agent WINDOW_UPDATE authorizes agent-to-server DATA.
- A future request-direction feature can use the same message in reverse.

Flow state is scoped by concrete backend stream, logical connection, and
direction. A reconnect creates a new scope with counters starting at zero.

### Enablement

The server and agent binaries each expose the startup-only boolean flag
--enable-http-connect-flow-control, default false. The server flag controls
whether new backend streams offer response V1. The agent flag controls whether
new client streams are willing to accept response V1. Both flags must be true
for response V1 to be negotiated. When either flag is false, conforming peers
use the unchanged legacy path and create no response flow-control state.

The flag name deliberately reserves one operator-facing control for HTTP
CONNECT flow control. In this version it enables only agent-to-server response
DATA flow control; server-to-agent request DATA remains legacy. Both binaries'
flag descriptions state that limitation. A future request-direction protocol
requires its own reviewed design and negotiation feature, but not another CLI
enablement flag.

Offer and acceptance policy are immutable for the process lifetime and are
snapshotted for each new backend or client stream. Changing either flag
requires a restart and never changes an established connection in place.

### Negotiation

Negotiation is per dial:

1. An enabled server offers AGENT_TO_SERVER_BYTE_WINDOW_V1 in DIAL_REQ; a
   disabled server sends no offer. An offer grants zero bytes and consumes no
   pool capacity.
2. An enabled agent ignores unknown features and accepts only features it
   implements and will enforce. A disabled agent accepts nothing.
3. After a successful endpoint dial, the agent installs zero-credit response
   state before sending a successful DIAL_RSP that accepts response V1.
4. An absent or unaccepted feature selects the legacy path.
5. A selected feature is immutable for that logical connection.

Validation rules:

- Empty or absent offered and accepted sets mean legacy.
- Feature value zero is never negotiated.
- Unknown offered features are ignored.
- Duplicate features and accepted-but-not-offered features are malformed.
- A malformed positive response fails the dial before HTTP 200.
- No capability is inferred from a product version.
- A positive selection never falls back to legacy because capacity is
  unavailable.

For server-created HTTP-CONNECT dials, offer policy is fixed for the lifetime of
a backend stream. Agent acceptance policy is also fixed for its client stream.
Before publishing a connection, the server atomically latches the response mode
selected by the first successful eligible DIAL_RSP on that backend stream.
Every later successful eligible DIAL_RSP must select the same mode. A mode
change fails before connection publication.

This stream-homogeneous policy prevents a blocked legacy HTTP response from
sharing a server receive stream with negotiated response DATA whose
WINDOW_UPDATE processing depends on that stream. The latch is a defensive
consistency backstop for malformed peers or implementation and policy bugs;
mixed-mode transitions are not an expected operating path.

### Cumulative byte limit

Sender state:

- sendLimit: greatest max_data_offset received.
- committedTotal: endpoint bytes read and committed to the tunnel, including
  bytes waiting for serialized gRPC Send.
- sentTotal: committed bytes whose ordered DATA Send completed successfully.
  This is send-progress accounting and observability, not the endpoint-read
  credit gate.

Receiver state:

- grantLimit: greatest max_data_offset committed for publication.
- receivedTotal: valid DATA bytes received.
- consumedTotal: bytes accepted by the HTTP socket.
- W: fixed receive capacity reserved for this connection.

The invariants are:

~~~text
sentTotal <= committedTotal <= sendLimit
consumedTotal <= receivedTotal <= grantLimit
grantLimit - consumedTotal <= W
~~~

committedTotal is the sender's credit-enforcement counter: endpoint reads are
limited by sendLimit minus committedTotal, not by sentTotal. sentTotal advances
only after a successful DATA Send and must never exceed committedTotal. A Send
failure is terminal for the backend generation; committed bytes are not rolled
back or retried because delivery may be ambiguous.
Terminal sender failure stops silent continuation and terminates the tunnel
promptly. This does not promise that every frontend protocol can distinguish
the resulting EOF from a normal close.

All counters start at zero. After the complete HTTP 200, the server publishes
the initial limit W. When the HTTP writer accepts n bytes, the server may reuse
that capacity:

~~~text
target grant limit = consumedTotal + W
~~~

The server may publish a lower value. It may not publish a higher value unless
the additional capacity is reserved.

Exactly one producer goroutine owns endpoint Read and committedTotal for each
connection direction. Before each Read it:

1. Snapshots sendLimit.
2. Computes sendLimit minus committedTotal.
3. Limits the Read buffer to that allowance and the maximum DATA frame size.
4. Performs the Read without holding the accounting lock.
5. Advances committedTotal before publishing the returned bytes to any send
   queue.

At zero allowance the producer waits on per-connection state. Local close,
backend failure, agent shutdown, or dial teardown cancels the wait and closes
the endpoint socket to interrupt a blocked Read.

DATA consumes len(data) bytes. The receiver uses checked arithmetic and rejects
negotiated DATA that would make receivedTotal exceed grantLimit. Empty DATA is
invalid in negotiated mode. Duplicate or lower WINDOW_UPDATE values are
idempotent; a larger value advances sendLimit and wakes only the named
connection. Counters must not wrap during a live connection.

### WINDOW_UPDATE publication

The server commits a new grantLimit before the corresponding WINDOW_UPDATE can
be visible to the agent. This prevents valid immediate DATA from being rejected
against stale local state.

Updates are cumulative and may be coalesced per connection. At most one update
per connection is pending or in flight; a newer value replaces an older
unsent value. A connection enqueues only a dirty marker, not one queue item per
HTTP write.

The backend sender must schedule dirty connections fairly. A delayed
Backend.Send does not hold a connection accounting lock. Send failure is
terminal for the backend generation; grantLimit is not rolled back because the
peer may have received the update.

## Memory and admission

### Configuration

In addition to its enablement flag, the server exposes four direction-neutral
HTTP-CONNECT flow-control tuning settings. The names describe local receive
capacity rather than a wire direction. In this version only the server exposes
them, and they configure agent-to-server response DATA; server-to-agent request
DATA remains legacy. Their flag descriptions state that limitation. A future
request-direction implementation can expose the same names on the agent for
its local receive capacity, with values configured independently for each
binary. They have no effect on legacy connections when the flag is disabled or
response V1 is not negotiated:

| Setting | Default | Meaning |
| --- | ---: | --- |
| --http-connect-flow-control-window-size | 64Ki | Receiver-local W reserved for each admitted flow and advertised to that flow's sender. |
| --http-connect-flow-control-pool-size | 128Mi | Maximum aggregate flow-control receive capacity reserved by one process. |
| --http-connect-flow-control-max-pending-admissions | 256 | Maximum negotiated connections waiting for receiver-local capacity; zero disables waiting. |
| --http-connect-flow-control-admission-timeout | 1s | Initial maximum receiver-side admission wait; subject to Phase 4 validation and deployment-specific deadline guidance below. |

The agent negotiates the feature, not a numeric window. It obeys the cumulative
limits published by the server.

These four defaults are initial tuning values, not protocol constants. Phase 4
must validate all of them before they are finalized. In particular, 1s is a
provisional short admission wait, not a claim that every frontend has a longer
deadline.

Validation requirements:

- Window and pool sizes are positive.
- Pool size is at least one window.
- Pending-admission count is non-negative.
- A non-empty admission queue requires a positive timeout.

Admission must finish within the frontend deadline remaining after backend
selection, DIAL_REQ delivery, endpoint dialing, and DIAL_RSP. Operators must
therefore configure the admission timeout sufficiently below the shortest
expected end-to-end frontend CONNECT/dial deadline to leave margin for those
steps and the HTTP response write. Merely setting it below the original
frontend timeout is necessary but not sufficient. Otherwise the caller can
give up first, making the remaining admission wait useless while endpoint and
connection state are still retained. The server cannot validate this relation
locally because caller deadlines are not a server configuration input. The
effective wait ends at the earliest of the admission timeout, frontend
cancellation or closure, an enabled server-side dial-establishment deadline,
backend or endpoint failure, and server shutdown. The existing
--backend-dial-timeout supplies that additional deadline only when it is greater
than zero. At its default of zero, its timer and HTTP 504 path are absent; the
admission timeout is the only server-configured timer during admission.

All four settings are startup-only and immutable for the process lifetime;
changing them requires a server restart. Live pool resizing, including shrink
behavior when existing reservations exceed a new limit, is outside this design.
A connection records W when admitted. W is not resized and published credit is
not revoked during that connection.

For fixed W, the maximum reservation count is:

~~~text
floor(pool size / W)
~~~

At startup, the server logs the validated window size, pool size, exact maximum
reservation count, pending-admission limit, and admission timeout. The derived
count is the ceiling for response-V1 reservations governed by this pool, not a
limit on all server connections.

The pool must remain below the process memory limit with headroom for protobuf
allocations, connection state, goroutines, the shared gRPC receive path, runtime
overhead, and kernel socket buffers. Every advertised but unconsumed byte is
charged to the pool even if physical buffer pages are allocated lazily.

### Admission queue

The allocator is consulted only after a successful DIAL_RSP positively accepts
response V1.

If W is available, the server reserves it immediately. Otherwise the dial
enters a FIFO admission queue because every waiter requests the same W. The
queue:

- Exists only before HTTP 200.
- Is bounded by connection count, not bytes.
- Contains no response DATA.
- Holds zero response credit.
- Does not block the shared backend receiver.
- Is cancellable when the frontend, backend, endpoint, or server disappears.

The admission timeout is its own policy timer, but admission does not create a
parallel connection-lifecycle or socket-ownership path. A successful DIAL_RSP
first atomically claims the PendingDial entry, then registers any waiter with
the connection's existing terminal state. The Tunnel's closed, backend-context,
shutdown, and optional backend-dial-timeout paths cancel that waiter through the
same abort path. They release its queue slot, endpoint, and any assigned
reservation exactly once. The backend-dial timer is not re-armed for admission;
the connected success signal is emitted only after the complete HTTP 200.

When capacity is released, the allocator selects the next live waiter,
revalidates the frontend, backend generation, endpoint, and selected mode, and
then transfers ownership of W to that connection.

Admission outcomes are:

Condition means the admission transition that linearizes first in the
connection's shared state: capacity assignment or one terminal outcome, not
merely an event observed by a racing goroutine. For a terminal transition,
Frontend result is the response that winner attempts; socket closure or write
failure can still prevent delivery. If another transition wins first, its row
applies and the admission metric records that winner exactly once. A later
lifecycle failure does not rewrite a completed admission outcome.

| Condition | Frontend result | Endpoint cleanup |
| --- | --- | --- |
| Capacity assigned | Continue establishment | Keep open |
| Queue disabled | Attempt complete HTTP 503 through the sole writer before HTTP 200 | Send one backend close if live |
| Queue full | Attempt complete HTTP 503 through the sole writer before HTTP 200 | Send one backend close if live |
| Admission timeout | Attempt complete HTTP 503 through the sole writer before HTTP 200 | Send one backend close if live |
| Enabled backend-dial timeout wins during admission after DIAL_RSP claim | Connection-owned abort; no direct Tunnel write | Send one backend close if live |
| Frontend cancelled | Write no response | Send one backend close if live |
| Backend or endpoint failed | Attempt HTTP 502 before HTTP 200 when writable | Release local state |
| Server shutdown | Close frontend | Send one backend close if live |

Every outcome removes the waiter and releases local state exactly once. A
positively negotiated dial is never downgraded to legacy, and an established
slow connection is never terminated to make room for a new dial.

PendingDial.Remove is the socket-ownership handoff. Before a DIAL_RSP claims the
entry, the Tunnel goroutine may serialize a fixed error response only when its
own Remove succeeds. This is the only case in which an enabled
--backend-dial-timeout produces HTTP 504. After the DIAL_RSP Remove succeeds,
the connection owns all terminal socket I/O. An admission 503 uses the same sole
HTTP-writer primitive as HTTP 200, configured with a fixed error response.
Success and error attachment compete under the same connection mutex for the
same single writer slot and terminal latch; at most one can attach, and a losing
path must not start, mutate, or repurpose the winner. A Tunnel terminal arm that
observes Remove returning nil calls abortHTTP instead of writeAll.

Admission failure selection and error-writer attachment are one linearized
transition. If a different terminal outcome already won, the attachment fails,
that outcome's table row and metric apply, and no 503 is attempted. If admission
failure wins, its writer attempts the complete 503, but a later socket close or
write failure can still prevent delivery. The client-visible guarantee is that
failed admission never produces HTTP 200 or tunnel success, not that HTTP 503
delivery is infallible.

Capacity assignment and admission failure linearize before the successful HTTP
writer is installed. Therefore an admission 503 cannot occur after that writer
is installed. Once installation wins, every later failure aborts the writer;
after any HTTP 200 byte has been written, no alternate HTTP status is legal.

### Connection buffer

After admission, install a reservation-backed byte FIFO, preferably a byte ring
or chunked byte buffer. TCP DATA packet boundaries have no meaning and need not
be retained. A byte-oriented buffer prevents one-byte DATA frames from creating
traffic-dependent queue-node growth.

The shared backend receiver validates and copies in-window DATA into the
reserved FIFO without performing HTTP socket I/O or waiting for ordinary FIFO
space. Valid DATA cannot encounter ordinary overflow because its capacity was
reserved before the agent received permission to read it. Failure to insert
valid DATA is an accounting invariant failure, not congestion and not a
slow-reader condition.

Control and terminal events have separate bounded capacity so DATA pressure
cannot prevent cleanup. The shared recvCh and maximum protobuf frame must be
included in the memory budget or structured so they cannot form a second
unaccounted DATA backlog.

## Endpoint and lifecycle behavior

### Server response receiver

1. Send DIAL_REQ with response V1 offered and zero credit.
2. On an unsuccessful DIAL_RSP, return the existing dial error before HTTP 200
   without consulting the flow-control allocator.
3. On a successful legacy DIAL_RSP, enter the legacy path without consulting
   the allocator or admission queue.
4. On a successful response-V1 DIAL_RSP, reserve W or enter admission.
5. After admission, install the byte FIFO, counters, terminal state, and sole
   HTTP writer before publishing the connection.
6. The sole writer writes the complete HTTP 200. Partial progress continues
   until complete; zero progress or an error is terminal.
7. After the complete 200, publish the initial WINDOW_UPDATE with limit W.
8. For DATA, validate connection ownership, backend generation, negotiated
   mode, frame size, and grantLimit. Copy valid bytes to the reserved FIFO and
   return without socket I/O.
9. The writer drains FIFO bytes in order. Every positive HTTP Write result
   advances consumedTotal by exactly n and makes n bytes eligible for a later
   cumulative grant.

Once any byte of HTTP 200 is written, no alternate HTTP status is legal. A
partial-200 failure closes the socket. Failures after the complete 200 are
tunnel closure, not HTTP error responses.

### Agent response sender

1. Attempt the endpoint dial before sending DIAL_RSP.
2. On failure, send an unsuccessful DIAL_RSP and create no response-flow state.
3. On success, install zero-limit state and a cancellable credit wait before
   sending the successful DIAL_RSP.
4. Start one endpoint-read producer. In negotiated mode it waits because
   sendLimit is zero.
5. WINDOW_UPDATE processing monotonically advances sendLimit for the named
   connection and wakes that producer.
6. The producer reads no more than the current allowance and maximum frame
   size, advances committedTotal, and sends ordered DATA.
7. If Read returns bytes with EOF, send those bytes before closing.
8. Teardown wakes the credit wait and closes the endpoint socket.

Endpoint bytes may arrive before positive credit, but the agent performs no
userspace Read. Those bytes remain in the endpoint socket receive buffer and
ordinary TCP backpressure stops further production. They do not enter sendCh,
the gRPC stream, or server memory.

### Close and failure ordering

- HTTP 200 and tunneled response DATA have one socket-write owner.
- Admission assignment, cancellation, and failure are linearized so exactly one
  outcome owns W or cleanup.
- No positive WINDOW_UPDATE is sent before the complete HTTP 200.
- CLOSE_RSP stops new grants. DATA already sent within the prior grant and
  ordered before close is drained before graceful frontend close.
- Frontend EOF sends at most one CLOSE_REQ and stops new grants.
- Write failure, backend failure, and reconnect wake all waits and release the
  byte FIFO and W exactly once.
- State removal is conditional on the concrete backend generation and expected
  connection object so stale cleanup cannot delete a replacement connection.
- Reconnect clears selected features, counters, grants, reservations, pending
  updates, admission state, and the stream mode latch.

### Compatibility

| Server | Agent | Result |
| --- | --- | --- |
| Pre-feature | Pre-feature | Legacy behavior. |
| Pre-feature | New, flag enabled | No offer; agent selects nothing and uses legacy behavior. |
| New, flag enabled | Pre-feature | Agent ignores the additive offer; server receives no selection and uses legacy behavior. |
| New, flag enabled | New, flag enabled | Response V1 is negotiated; request DATA remains legacy. |
| New, flag disabled | New, flag enabled | No offer; deliberate legacy behavior. |
| New, flag enabled | New, flag disabled | No acceptance; deliberate legacy behavior. |

At least one CI job runs a new server against a selected pre-feature agent
binary and a new agent against a selected pre-feature server binary. New-schema
mocks alone do not prove old-process behavior.

### Known limitation

The agent currently handles server-to-agent request DATA and WINDOW_UPDATE on
one serial receive loop. If request DATA for connection X blocks dispatch to
its endpoint, a later WINDOW_UPDATE for response connection Y cannot be
processed. Y safely reaches zero credit and remains memory-bounded, but it may
pause until X unblocks.

This design does not claim complete bidirectional liveness or control-path
scheduling isolation. A request-direction flow-control follow-up must prevent
endpoint I/O or ordinary buffer space from blocking that receive loop.

## Test plan

### Tests first

The tests are the executable contract and are introduced in dependency order.
A contract tranche may depend on completed prerequisite production behavior,
but it must land before the production behavior it governs. Only completed
prerequisite behavior, the additive schema and generated types, and test seams
needed to compile a tranche may precede that tranche.

Every contract tranche must compile and fail at expected behavioral assertions
before its production implementation is added, not because of missing symbols,
panics, sleeps, or test timeouts. Record the expected failures in the PR
description. Later implementation commits make the same assertions pass.
Contract assertions may be changed only as a separately reviewed design
correction.

Correctness tests use explicit response-started, response-complete, grant-sent,
DATA-received, write-released, and worker-completed signals. Timeouts are
failure bounds only; timeout expiry is never an accepted expected failure.

A contract belongs in the earliest tranche whose setup can reach its assertion
without implementing the production behavior under test in a fake or waiting
for a missing prerequisite until a safety timeout. Do not add placeholder
resource machinery solely to make a later contract compile.

Agent sender contracts use a protocol-aware fake server. Server component
contracts that do not require the production sender use a protocol-aware fake
agent, which must observe the actual DIAL_REQ and may accept response V1 only
after finding it in that request's offered feature set. Server validation still
uses the offer recorded for the dial. The primary HOL proof uses the real
recorded offer and acceptance path and the production agent sender.

### Primary HOL proof

The primary proof is authored at the head of Phase 3, after Phase 2 provides the
production agent sender and endpoint-read gating. It must not inject an
accepted feature or manufacture negotiation state. Before the Phase 3
response-flow receiver exists, a missing initial grant or other missing server
state must be observed at an explicit protocol checkpoint; waiting for B until
a safety timeout is not a valid expected failure.

One deterministic test must prove the complete outcome:

1. Establish negotiated connections A and B on the same backend stream.
2. Block A's HTTP writes and make the endpoint offer substantially more DATA
   for A than W and the test's bounded-buffer threshold.
3. Verify A reaches zero credit, stops endpoint reads, remains open, and creates
   no traffic-dependent DATA backlog.
4. Verify B completes its dial and transfers response DATA while A remains
   blocked.
5. At explicit checkpoints, verify fixed buffer, reservation, worker, and
   connection counts.
6. Release A and verify it resumes at the exact next byte without loss,
   duplication, or reordering.

A synchronous shared-writer implementation fails because B stalls. A
queue-only implementation fails because A eventually overflows. The
flow-control implementation must satisfy all six assertions together.

### Negotiation and compatibility tests

- Both binaries register --enable-http-connect-flow-control with a false
  default and a description that identifies the response-only limitation.
- A disabled server sends no offer; an enabled server offers exactly response
  V1. A disabled agent accepts nothing even when response V1 is offered.
- Every compatibility-matrix pairing establishes, transfers DATA in both
  directions, and closes.
- Failed DIAL_RSP creates no flow state, reservation, admission waiter,
  HTTP 200, or WINDOW_UPDATE.
- A pre-feature agent never consults the flow-control pool and remains
  successful when that pool is exhausted.
- Empty and unknown offers select the expected subset.
- Duplicate and accepted-but-not-offered features fail before HTTP 200.
- Concurrent first responses latch exactly one stream mode; later mode changes
  fail before connection publication.
- A future unknown directional feature does not disable response V1.
- Reconnect clears all flow-control and stream-policy state.
- No legacy case emits or waits for WINDOW_UPDATE.

### Byte-window and ordering tests

- Agent response state starts at zero and performs no endpoint Read before the
  initial grant.
- Zero-limit state exists before successful response-V1 DIAL_RSP.
- Delayed reader scheduling or WINDOW_UPDATE processing produces no pre-grant
  DATA or accounting change.
- No byte of HTTP 200 is written while admission is pending.
- The complete HTTP 200 precedes the initial grant and response DATA.
- A partial-200 failure closes without attempting another HTTP status.
- DATA exactly equal to remaining credit succeeds.
- DATA before grant, one byte beyond credit, empty DATA, unknown connection,
  stale generation, and arithmetic overflow are rejected without affecting
  another connection.
- Duplicate or lower updates are idempotent; a higher update wakes only its
  connection.
- committedTotal, including any sendCh storage, never exceeds sendLimit.
- committedTotal, sentTotal, and successful DATA Sends advance in order;
  sentTotal advances by exactly the successfully sent bytes and never gates a
  permitted endpoint Read.
- A DATA Send failure is terminal, does not roll back committedTotal, and does
  not retry bytes whose delivery is ambiguous.
- If DATA Send fails with committedTotal greater than sentTotal, teardown
  discards the committed-but-unsent backlog without converting it into new
  credit or a retry. The corresponding backend-generation cleanup releases the
  server buffer and W exactly once, and active gauges converge without counter
  underflow or accounting corruption.
- grantLimit minus consumedTotal never exceeds W.
- Every increase in advertised but unconsumed credit is covered by reservation
  before publication.
- A blocked HTTP Write creates no replacement credit.
- Partial writes grant only bytes actually accepted.
- Update coalescing keeps at most one pending or in-flight marker per
  connection.
- Publication raced with immediate valid DATA never falsely rejects that DATA.
- Explicit fair or round-robin scheduling across simultaneously readable
  agent endpoints is not part of this response HOL fix; the existing
  agent-to-server DATA send scheduling remains unchanged.

### Admission and memory tests

- Defaults and invalid configurations are covered.
- A configured pool admits exactly floor(pool size / W) reservations.
- The startup capacity summary uses that exact derived reservation count and
  reports the configured window, pool, pending limit, and admission timeout.
- Pending waiters consume no DATA capacity.
- Reservation exhaustion waits without DATA, HTTP 200, or shared-receiver
  blockage.
- Releasing W admits the next live FIFO waiter.
- Cancelling a waiter removes it promptly.
- Queue-disabled, queue-full, and admission-timeout outcomes that win attach the
  shared connection-owned writer slot with a complete HTTP 503 after the
  successful DIAL_RSP claim; the Tunnel goroutine performs no competing socket
  write. A successful writer emits the complete 503.
- If another terminal outcome wins before the 503 transition, no 503 is
  attempted, that outcome is recorded exactly once, and no HTTP 200 is written.
- With --backend-dial-timeout at its zero default, no backend-dial timer or HTTP
  504 path exists and the admission timer still bounds the wait.
- With --backend-dial-timeout enabled, expiry before DIAL_RSP claims PendingDial
  returns HTTP 504. Expiry during admission after the claim cancels the waiter
  through abortHTTP and causes no direct Tunnel socket write.
- Backend and endpoint failure outcomes that win emit complete HTTP 502 before
  HTTP 200 when the connection-owned writer succeeds.
- Frontend cancellation writes no response.
- With capacity unavailable, frontend cancellation or closure before a longer
  admission timer removes the waiter promptly, assigns or leaks no reservation,
  and closes the endpoint at most once.
- Shutdown closes the frontend.
- Every terminal outcome releases waiter state and requests endpoint close at
  most once when the endpoint may still be live.
- Many blocked admitted flows retain fixed reservations; sustained endpoint
  production does not grow response memory with traffic volume.
- One-byte DATA frames do not cause queue-node growth.
- A delayed agent retains unused credit and W, sends no DATA, and resumes or
  tears down without accounting corruption.
- Long-running resource tests compare heap, goroutine, connection, buffer, and
  reservation counts before and after sustained pressure.

### Close and race tests

- Race frontend EOF, endpoint EOF, outstanding credit, in-flight DATA,
  CLOSE_REQ, CLOSE_RSP, write failure, backend shutdown, admission assignment,
  cancellation, and reconnect.
- Race PendingDial claim, capacity assignment, admission timeout, optional
  backend-dial timeout, error/success writer attachment, and partial HTTP 200;
  exactly one socket owner and terminal outcome wins.
- Error and success attachment contend for one shared writer slot; the losing
  path cannot start, mutate, or repurpose the attached winner.
- DATA ordered before close drains; post-terminal DATA cannot revive a
  connection.
- After a negotiated connection owns W, its byte FIFO, and its writer, trigger
  a connection-owned abort or write failure without sending CLOSE_RSP. The byte
  FIFO, W, worker ownership, and gauges must release exactly once without
  waiting for that acknowledgement. Any separately reviewed late-DATA
  tombstone policy is orthogonal: a retained map entry must not retain those
  flow-control resources.
- Credit waits, buffers, reservations, workers, map entries, and metrics
  converge exactly once under the race detector.
- A stale writer or backend generation cannot remove a replacement connection.

### Metrics tests

- Gather every metric below and assert its exact name, type, labels, and allowed
  label values.
- Drive legacy, negotiated, zero-credit, resumed, admission, violation, and
  teardown scenarios and assert the corresponding values change exactly once.
- After teardown, active-connection, buffered-byte, reserved-byte, and
  pending-admission gauges return to their prior values.
- Reject connection IDs, dial IDs, destinations, and UUIDs as metric labels.
- Verify queue-overflow disconnect is not reported as successful backpressure.

## Observability

Keep existing receive-channel, packet, stream-error, connection, dial, and
write-latency telemetry. The names below omit the existing
konnectivity_network_proxy_server_ or konnectivity_network_proxy_agent_ prefix:

| Owner | Metric suffix | Type | Labels | Meaning |
| --- | --- | --- | --- | --- |
| Server | http_connect_connections_by_mode | Gauge | mode | Live HTTP-CONNECT connections after mode selection. |
| Server | flow_control_bytes_total | Counter | direction, stage | Byte deltas committed at granted, received, and consumed. |
| Server | flow_control_outstanding_bytes | Gauge | direction | Sum of grantLimit minus consumedTotal. |
| Server | flow_control_buffered_bytes | Gauge | direction | Sum of receivedTotal minus consumedTotal. |
| Server | flow_control_pool_capacity_bytes | Gauge | direction | Configured process-wide reservation capacity. |
| Server | flow_control_pool_reserved_bytes | Gauge | direction | Capacity owned by admitted connections. |
| Server | flow_control_admission_pending | Gauge | direction | Current pre-200 admission waiters. |
| Server | flow_control_admission_wait_seconds | Histogram | direction | Completed admission wait duration. |
| Server | flow_control_admission_total | Counter | direction, outcome | Admission outcomes. |
| Server | flow_control_window_updates_coalesced_total | Counter | direction | Updates replaced before send by a newer cumulative value. |
| Server | flow_control_protocol_violations_total | Counter | direction, reason | Negotiated DATA rejected by validation. |
| Agent | flow_control_connections | Gauge | direction, credit_state | Negotiated connections at zero or positive credit. |
| Agent | flow_control_bytes_total | Counter | direction, stage | Byte deltas at limit_received, committed, and sent. |
| Agent | flow_control_zero_credit_duration_seconds | Histogram | direction | Time at zero credit, observed on resume or teardown. |

Allowed label values:

- direction: agent_to_server.
- mode: legacy, agent_to_server_byte_window_v1.
- server stage: granted, received, consumed.
- agent stage: limit_received, committed, sent.
- credit_state: zero, positive.
- outcome: admitted, queue_disabled, queue_full, frontend_cancelled,
  backend_closed, endpoint_closed, timed_out, shutdown.
- reason: before_grant, credit_exceeded, empty_data, unknown_connection,
  stale_generation, counter_overflow.

The existing stream-packet metric reports actual WINDOW_UPDATE packets. The
existing server dial_failure_count adds flow_control_feature_mismatch and
flow_control_admission_failed; flow_control_admission_total carries the detailed
outcome. Histograms use the existing bucket set for their subsystem.

No metric is labelled by connection ID, dial ID, destination, agent UUID,
server UUID, or cumulative offset. A future request-direction implementation
adds server_to_agent to the existing direction label rather than introducing
parallel metric families.

Alert on sustained reservation saturation, growing or long-lived admission
waits, and material admission-refusal rates. Zero-credit duration represents
normal backpressure and becomes actionable when sustained or correlated with
application failures.

## Implementation

### Reusable server primitives

Reuse the HTTP-CONNECT ownership and lifecycle primitives where their semantics
match this design. The DATA queue and overflow policy are not part of response
flow control.

| Server primitive | Treatment | Required change |
| --- | --- | --- |
| One connection-owned HTTP writer goroutine | Adapt | Keep sole socket-write ownership; drain a reservation-backed byte FIFO instead of a packet channel. |
| Complete HTTP 200 serialization and connected notification | Adapt | Start only after admission and state installation; publish initial credit only after the complete 200. |
| Initial/error response serialization | Reuse | Continue using bounded error bodies and complete HTTP response serialization. After DIAL_RSP claims PendingDial, configure the same connection-owned writer primitive and shared attachment slot with the admission error; do not write it from Tunnel. |
| writeAll helper | Partial reuse | Use for fixed HTTP responses; DATA writes must expose every positive n so consumedTotal advances exactly. |
| Writer attach and terminal-state ownership | Adapt | Use one connection mutex, terminal latch, and writer slot for mutually exclusive success and error attachment; add negotiated mode, buffer, counters, and reservation ownership. |
| Exact-once frontend close and backend CLOSE_REQ guards | Adapt | Also wake credit/admission waits and release W exactly once. |
| Conditional established-map removal | Reuse | Continue matching the expected connection and concrete backend generation. |
| Pending-dial ownership and connected/closed signalling | Adapt | Preserve PendingDial.Remove as the DIAL_RSP claim handoff. Track the claimed pre-200 connection through admission; signal connected only after the complete HTTP 200. |
| Backend-shutdown and setup-race cleanup | Reuse and extend | Include flow state, dirty updates, admission waiters, byte buffers, and reservations. |
| Packet-count DATA channel | Remove | Replace with the byte FIFO backed by W. |
| Non-blocking DATA enqueue and overflow disconnect | Remove | Valid in-window DATA has reserved capacity and cannot overflow during ordinary operation. |
| Queue-size configuration and overflow metrics | Remove | Replace with window, pool, admission, zero-credit, and protocol metrics. |
| Existing HOL, ordering, and lifecycle test intent | Adapt | Negotiate response V1 and assert credit, memory, ordering, and exact-once lifecycle behavior. |

The reusable portion is the control and lifecycle shell: socket ownership,
HTTP response ordering, connection publication, generation-safe removal, and
exact-once cleanup. The response DATA engine is replaced: buffering,
enqueueing, overflow handling, draining, and consumption accounting all change.

### Phase 0: schema, baseline, and negotiation executable contract

- Add the schema and generated types without production flow-control behavior.
- Add the protocol setup and test seams required by the Phase 1 contract.
- Retain and adapt the HTTP ownership, lifecycle, ordering, HOL, and
  legacy-behavior tests and reusable test harnesses that establish the
  pre-feature regression baseline. These remain-green baseline tests are not
  expected-red flow-control contract tranches.
- Add or adapt the deterministic wire, negotiation, and compatibility tests.
- Produce and record their expected semantic failures before adding Phase 1
  production behavior.

### Phase 1: negotiation and compatibility

- Add the default-off server and agent enablement flags and snapshot their
  offer and acceptance policy per stream.
- Implement feature parsing and validation.
- Latch the selected response mode before connection publication.
- Make wire, negotiation, and compatibility tests pass.

### Post-Phase-1 contract gate

- Add the agent sender contract tranches driven by a protocol-aware fake
  server.
- Add server window, allocator, admission, and ordering contract tranches whose
  setup is reachable with a protocol-aware fake agent. These tests are
  independent of Phase 2 because the fake supplies controlled protocol
  responses and DATA only after observing the real recorded offer.
- Add each metric contract in the earliest tranche where its producing
  transition is reachable. Descriptor absence is a valid semantic failure only
  when eager registration is the behavior under test; emission and lifecycle
  tests must reach the transition whose metric they assert.
- Keep the tranches small and record each explicit semantic failure before its
  production implementation.
- Defer the real-agent primary HOL proof and lifecycle contracts that require
  acquired Phase 3 resources to their earliest reachable Phase 3 tranche. Do
  not create placeholder resources or use timeout expiry to force them red.

### Phase 2: agent sender

- Add zero-limit state, monotonic update handling, cancellable waits,
  endpoint-read gating, committed-byte accounting, and frame limits.
- Install state before successful response-V1 DIAL_RSP.
- Keep server-to-agent request DATA unchanged.
- Make agent contract tests pass under the race detector.

### Phase 3: server receiver

- Add the primary HOL proof before the Phase 3 receiver behavior it governs,
  using the real Phase 2 sender and the real recorded negotiation path.
- Add resource-dependent lifecycle contracts at their earliest reachable Phase
  3 subphase and before the cleanup behavior they govern. This includes proving
  that local flow-control resources release without a CLOSE_RSP.
- Add validated window, pool, and admission configuration.
- Add the aggregate allocator and FIFO admission queue.
- Register admission cancellation with the claimed connection's existing
  connected/closed, backend-context, shutdown, abortHTTP, and optional
  backend-dial-timeout lifecycle. Do not re-arm the backend-dial timer.
- Preserve PendingDial.Remove as the socket-ownership handoff. Route every
  post-claim error response or abort through the connection-owned writer and
  terminal state, never a Tunnel writeAll.
- Make admission-failure selection and error-writer attachment one transition
  on the same slot used by the successful writer. A losing transition cannot
  modify or start the winner.
- Replace the packet DATA channel and overflow path with the reservation-backed
  byte FIFO.
- Add grant validation, consumption accounting, and coalesced WINDOW_UPDATE
  publication.
- Gate complete HTTP 200 and initial credit in the required order.
- Extend close, failure, reconnect, and backend-generation cleanup.
- Add the specified metrics.
- Make every deterministic contract test authored through Phase 3 pass.

### Phase 4: performance and resource gate

Add the resource-soak harnesses before performance tuning. They measure the
completed resource model rather than requiring placeholder resource machinery
in an earlier phase.

From Phase 4 onward, run deterministic correctness tests separately from
long-running resource and soak tests.

Measure:

- Streaming response throughput across representative RTTs.
- Webhook latency.
- Exec, attach, port-forward, and log-stream response throughput.
- CPU, heap, allocations, goroutines, file descriptors, and kernel socket
  memory.
- Fairness and WINDOW_UPDATE rate.
- Pool saturation and admission wait behavior.

Resolve the four provisional defaults and validate supported non-default values
against the reviewed memory and frontend-deadline budgets. Tuning may change
throughput, admission latency, and reservation concurrency; it must not change
safety behavior.

### Expected implementation areas

- konnectivity-client/proto/client/client.proto and generated files.
- pkg/agent/client.go and endpoint response state.
- pkg/agent/metrics.
- pkg/server/backend_manager.go for coalesced update scheduling.
- pkg/server/server.go for negotiation, admission, validation, dispatch, and
  terminal handling.
- pkg/server/http_connect_writer.go and pkg/server/tunnel.go for byte buffering,
  HTTP 200 gating, consumption, and cleanup.
- pkg/server/metrics.
- cmd/server/app/options, cmd/agent/app/options, and process construction for
  enablement and configuration.
- Server, agent, compatibility, race, and resource tests.

### Rollout and rollback

1. Deploy both new binaries with --enable-http-connect-flow-control=false and
   verify unchanged legacy dial and DATA behavior.
2. Enable the server flag first. Pre-feature and disabled agents ignore the
   additive offer and remain legacy without allocating flow-control resources.
3. Verify legacy behavior and zero negotiated admission activity, then enable
   the agent flag. New streams consistently select response V1; old streams
   remain legacy until reconnect.
4. Monitor mode, zero-credit duration, pool reservations, pending admissions,
   admission outcomes, heap, and disconnects.

Disabling either flag affects only streams created by the restarted process.
Existing streams retain their latched policy until drained or reconnected. An
established connection never changes mode in place.

### Acceptance gates

The response-flow implementation is complete only when:

- The primary HOL proof passes without disconnecting A or delaying B.
- Every contract tranche required by this plan has landed, and all
  deterministic contract tests pass under the race detector.
- Compatibility jobs with selected pre-feature binaries pass.
- No endpoint Read occurs before positive credit.
- DATA never exceeds the cumulative limit.
- Every published increase in unconsumed credit is backed by reservation.
- Admission and HTTP 200 follow the required state sequence.
- Blocked flows retain bounded memory and resume exactly.
- Close and failure races release state exactly once.
- Metrics pass descriptor, lifecycle, and bounded-cardinality tests.
- Resource tests show stable heap and goroutine counts under sustained
  backpressure.
- Admission refusal remains observable and rare at measured peak concurrency.

Verification commands:

~~~text
go test ./pkg/agent ./pkg/server ./konnectivity-client/proto/client
go test -race ./pkg/agent ./pkg/server
go test ./...
go vet ./...
~~~

Repeat concurrency-sensitive tests with a focused expression and -count=100.
