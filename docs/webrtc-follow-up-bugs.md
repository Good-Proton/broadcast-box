# WebRTC Follow-Up Bugs

Generated from the WebRTC audit on 2026-06-03. These findings were reviewed by sub-agents but were not fixed in the lock-leak pass.

## Resolved

### Stale WHIP DELETE Can Close A Newer Publisher

**Status:** WON'T FIX

**Rationale:**
The WHIP spec does not require clients to include session identifiers in DELETE requests, and the API is scoped by stream key, so the server cannot reliably distinguish a late DELETE from an old publisher versus a valid DELETE from the current publisher.

**Problem:**
`WHIPDelete` resolves the current stream by `StreamKey`, captures the current `stream.sessionId` and `stream.publisherConnection`, and closes that current publisher. A late DELETE from an older WHIP client is not distinguishable from the current publisher because the API path is stream-key scoped. The stale-session guard in `peerConnectionDisconnected` only works when the old session ID is passed in, but `WHIPDelete` passes the current session ID.

**Why it matters:**
After publisher A reconnects as publisher B, a delayed DELETE from A can close B and tear down the active publisher.

## Remaining Follow-Up Bugs

## 1. WHIP/WHEP Setup Errors Leave Partial Stream State

**Status:** confirmed follow-up bug

**Affected code:**
- `internal/webrtc/whip.go`: `WHIP`
- `internal/webrtc/whep.go`: `WHEP`

**Problem:**
Both setup paths mutate stream state before SDP setup is complete. WHIP can mark `hasWHIPClient`, update `sessionId`, and store `publisherConnection`; WHEP can store `subscriberConnections[whepSessionId]`. If `SetRemoteDescription`, `CreateAnswer`, or `SetLocalDescription` fails, the functions return without closing the peer connection or removing the partial stream/session state.

**Why it matters:**
Invalid offers or transient setup errors can leave orphaned publisher/subscriber state that affects later status responses, cleanup, and data-channel pairing.

**Suggested tests:**
- call `Configure()`
- call `WHIP("invalid sdp", streamInfo)`
- assert it returns an error and leaves no publisher state for that stream
- call `WHEP("invalid sdp", streamInfo)`
- assert it returns an error and leaves no subscriber connection/session state

The cleanup should happen on every synchronous setup error path, not only via `peerConnectionDisconnected`.

## 2. Status Reads Data-Channel Maps Without `dataChannelsLock`

**Status:** confirmed race risk

**Affected code:**
- `internal/webrtc/webrtc.go`: `GetStreamStatuses`
- data-channel map mutations in `ensureDataChannelPair` callbacks

**Problem:**
`GetStreamStatuses` reads `len(stream.publisherDataChannels)` while data-channel callbacks mutate `publisherDataChannels` and `subscriberDataChannels` under `stream.dataChannelsLock`. `streamMapLock` does not protect those callback writes, so this is an unlocked map read concurrent with locked map writes.

**Why it matters:**
This can trigger a Go data race and, in the worst case, `fatal error: concurrent map read and map write`. It affects `/api/status` and Prometheus collection paths that call `GetStreamStatuses`.

**Suggested test:**
Add a race-detector-focused test:
- create a stream with initialized data-channel maps
- one goroutine repeatedly adds/deletes `publisherDataChannels` entries under `dataChannelsLock`
- another goroutine repeatedly calls `GetStreamStatuses()`
- run with `go test -race ./internal/webrtc`

**Likely fix:**
Take `stream.dataChannelsLock.RLock()` around data-channel map reads in `GetStreamStatuses`.

## 3. WHEP Data Channel Before Publisher Can Nil-Panic

**Status:** confirmed follow-up bug

**Affected code:**
- `internal/webrtc/whep.go`: WHEP `OnDataChannel` callback
- `internal/webrtc/webrtc.go`: `ensureDataChannelPair`

**Problem:**
`WHEP` can create a stream before any WHIP publisher exists, leaving `stream.publisherConnection == nil`. If the WHEP peer opens a data channel, the WHEP `OnDataChannel` callback calls `ensureDataChannelPair`. When no publisher data channel exists, `ensureDataChannelPair` calls `stream.publisherConnection.CreateDataChannel(...)` without checking for nil.

**Why it matters:**
A viewer that opens a data channel before the publisher exists can panic the server process.

**Suggested test:**
Create a WHEP offer with a data channel for a stream key that has no WHIP publisher, complete signaling, and assert the server does not panic when the callback runs.

If a full WebRTC callback test is too heavy, add a package-level testcase that constructs a stream with `publisherConnection == nil` and calls `ensureDataChannelPair` through the WHEP-style path, expecting a controlled error.

## 4. WHIP RTCP Reader Goroutine Repeats After Receiver Errors

**Status:** credible follow-up bug

**Affected code:**
- `internal/webrtc/whip.go`: `videoWriter` RTCP reader goroutine

**Problem:**
When `receiver.ReadRTCP()` returns an error, the code logs and uses `break`. In this context, `break` exits the `select` case, not the enclosing `for` loop. The goroutine then waits for the next ticker event and tries `ReadRTCP()` again until the whole stream context is canceled.

**Why it matters:**
After an old WHIP publisher disconnects while the stream remains alive, stale RTCP reader goroutines can linger and wake every second.

**Suggested test:**
Extend reconnect coverage:
- connect publisher A
- connect publisher B or keep a WHEP session alive so the stream context remains active
- close publisher A
- assert the old RTCP reader exits, using a test hook or bounded goroutine observation

**Likely fix:**
Return from the RTCP reader goroutine after terminal `ReadRTCP` errors instead of using `break`.
