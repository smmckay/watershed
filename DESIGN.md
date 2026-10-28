# Billion-Connection HTTP Server on a Minimal Userspace TCP Stack

*Design notes for a learning project.*

## 1. Motivation and requirements

### Why

This is a learning project, not driven by a work requirement. The aim is to build a userspace TCP stack whose defining constraint is **minimal per-connection state**. Existing stacks don't optimize for that, so the project avoids "reimplementing what's done better elsewhere." The target scenario is an HTTP server that could hold on the order of a billion mostly-idle connections.

For the scale claim to mean anything in a real deployment, TLS has to be in scope. Holding a billion plaintext connections behind a TLS-terminating proxy or stateful load balancer just moves the problem to that box. Terminating TLS on the server, with minimal state, leaves open a deployment where traffic reaches servers through anycast/ECMP with no stateful middle tier.

### Requirements

- **Unmodified clients.** Standard TCP, TLS 1.3 and HTTP/1.1 clients must work, with no protocol changes on the client side. This rules out Trickles-style client-held transport state.
- **TLS 1.3 terminated on the server.** It can be a later milestone, but the earlier layers must be designed for it.
- **HTTP/1.1 only**, negotiated via ALPN, with keep-alive.
- **Primary metrics:**
  - bytes of server memory per idle connection, covering TCP, TLS and HTTP;
  - packets per second per core at a given connection count;
  - **reconnect cost**: CPU per reconnect, and recovery time after a mass disconnect.
- **Scale target.** Demonstrate 10–100M connections and extrapolate to 1B from measured bytes per connection. A real 1B run is optional, for example on a rented large-memory machine.

## 2. Constraints

### Why the kernel stack is out

- MigratoryData's 12M-connection benchmark measured about **46 GB of kernel memory for 12M sockets** on Linux 3.9, roughly **3.8 KB per idle connection**. At 1B connections that is about 4 TB.
- That much RAM exists, so the kernel isn't strictly impossible. In practice it's ruled out by per-process FD caps, epoll overhead, per-socket timers, and cache misses spread across terabytes of scattered state.
- A purpose-built connection record can plausibly use **64–128 B for TCP**. That's a 30–60× reduction and the core argument for the project.

### The workload must be mostly idle

- **Keepalive floor.** NATs and firewalls drop idle flows after minutes. At 1B connections with a 60 s keepalive, that's about 16.7M packets/s just to keep them alive.
- **Request floor.** One small request per connection per minute is also about 16.7M requests/s.
- In practice the scale target means "a high-end packet server with an unusually large connection table."

### No stateful middle tier

- Without a stateful load balancer, flows stay pinned only because of ECMP/anycast hashing. Adding or removing a server, or a route change, rehashes some flows to a server with no state for them, and those connections break.
- **Mass disconnection is expected**, so reconnect cost (mostly TLS handshake cost) is a first-class metric.
- **Reconnect storms.** A full TLS 1.3 handshake costs an ECDHE exchange plus a signature, tens of µs of CPU. A billion simultaneous reconnects is on the order of core-hours of work.

### TLS-specific constraints

- **Receive buffering.** AEAD can't verify a record until the whole record arrives, and TLS 1.3 records carry up to 16 KB of plaintext. One slow client sending large records forces up to 16 KB of buffering on that connection.
- **`record_size_limit` (RFC 8449)** can cap the records a client sends. The minimum value is 64, and the server sends it in EncryptedExtensions. The server can only send it if the client offered it.
- **Nonce reuse.** The per-record nonce is the IV XORed with the record sequence number (RFC 8446 §5.3). Encrypting *different* plaintext under the same record number is catastrophic with AES-GCM: it leaks the XOR of the plaintexts and allows forgeries.

### Testing constraints

- **4-tuple space.** One client IP connecting to one server IP:port gives about 64K connections. 1B connections needs about 15K+ distinct address pairs, which in practice means IPv6 or large alias blocks.
- **Load generator.** It must hold as many connections as the server, so it can't use a conventional stack.
- **Development hardware.** A laptop-class machine can't hold 1B connections at around 150 B each (about 150 GB).
- **Cloud networks** add their own per-flow state, such as connection tracking and per-instance flow limits. These may cap a cloud test below what the stack can hold.

### Assumptions to verify before relying on them

- [ ] Which mainstream TLS clients (browsers, OpenSSL, BoringSSL, rustls, Go, Java) send `record_size_limit` in their ClientHello.
- [ ] Connection-tracking and flow limits for the intended cloud instance type and network configuration.
- [ ] Linux `fs.nr_open` ceiling on the target kernel. My understanding is it's roughly 2³⁰; this only matters for kernel-stack comparisons.
- [ ] AF_XDP driver support (native vs. generic mode) on the development NIC.
- [ ] Current rustls API for `dangerous_extract_secrets()` and the unbuffered connection API at the version used.

## 3. Suggested design directions

### 3.1 Sans-IO core

- Write TCP, TLS and HTTP as pure state machines: packet or bytes in, packets and timer actions out. They have no sockets and no clock.
- The model is quinn-proto (QUIC) and, to a lesser degree, smoltcp.
- **Benefits:**
  - deterministic replay;
  - fuzzing;
  - in-process simulation at huge connection counts without NICs or address-space tricks;
  - I/O backends (simulator, AF_XDP, DPDK) are swappable.

### 3.2 The connection record

- **One packed, inline record per connection** in a single open-addressed table keyed by 4-tuple. There's no per-connection heap allocation: at 1B connections, every 8 B pointer costs 8 GB.
- **Layering in code, not in memory.**
  - Each layer's module owns a sub-struct inside the packed record and gets `&mut` access only to its part.
  - Pack the whole record as one unit to avoid padding between separately aligned sub-structs.
  - Enforce the size with a `const` assertion so regressions fail the build.
- **Derive rather than store** wherever possible:
  - ISN from a SYN-cookie-style keyed hash of the 4-tuple;
  - sequence state stored as small offsets from the ISN;
  - MSS and window scale as small enums;
  - TCP, TLS and HTTP state enums packed into one shared byte;
  - send-side TLS record numbers derived from the stream offset (see 3.4).
- **Compress the key.** Store only the part of the 4-tuple that the table hash doesn't already imply.
- **Rough budget:**

| Component | Approx. bytes |
|---|---|
| TCP control state | 64–128 |
| TLS steady state (keys/IVs or traffic secrets, rx seq, partial-record ref) | 60–90 |
| HTTP state (response id, response-start stream offset, parser bits) | ~8–16 |
| **Total** | **~130–180 → ~150 GB per 1B connections** |

### 3.3 No data buffering in the TCP layer

- **Offset-addressed sending.** TCP never owns payload data. For both first sends and retransmits, it asks the layer above for bytes `[a, b)` of the outgoing stream.
- **Regenerable responses.** The plaintext milestone serves content that can be recomputed from (resource id, byte offset), so idle connections hold zero buffer bytes.
- **Content immutability is a security invariant**, not just a convenience, once TLS is added (see 3.4). Snapshot a version id at the start of each response.
- **Receive side.**
  - Drop out-of-order segments rather than reassembling them.
  - Optionally refuse pipelined requests until the current response has finished.
- **Bounded shared pool** for the receive-side state that can't be avoided, such as TLS partial records. Use a global budget and eviction instead of per-connection buffers.

### 3.4 TLS 1.3 layer

- **Handshake via rustls, steady state self-owned.**
  - Run the handshake in rustls, in a bounded transient pool separate from the connection table.
  - Call `dangerous_extract_secrets()` (intended for kTLS) to get keys, IVs and sequence numbers, then drop the rustls connection object.
  - Write a minimal record layer for the steady state.
  - Replacing the handshake later is optional.
- **Fixed-size outgoing records.** Record *i* covers plaintext `[i·R, (i+1)·R)` of the response, so retransmits regenerate byte-identical ciphertext from the stream offset.
  - Store only the record number at the start of each response.
  - Never re-encrypt different plaintext under an already-used record number.
- **Memory/CPU tradeoff for keys.**
  - Idle tier: store only the two 32 B application traffic secrets and re-derive key/IV via HKDF when a record arrives. You need the secrets anyway to handle a client KeyUpdate.
  - Active tier: store expanded keys.
  - Never store AES round-key schedules (~176 B for AES-128); expand on the fly with AES-NI.
- **Sequence numbers.** Store fewer than 64 bits and force a KeyUpdate or close the connection before they wrap.
- **Receive side.**
  - Advertise `record_size_limit` when the client offers it.
  - Otherwise rely on a small TCP receive window plus the bounded partial-record pool.
- **Session tickets** make reconnects nearly stateless: the client holds resumption state and the server holds only the ticket-encryption key. Evaluate both resumption modes explicitly:
  - `psk_dhe_ke` keeps forward secrecy but pays for ECDHE on every reconnect.
  - `psk_ke` is purely symmetric and cheap, but gives no forward secrecy for resumed sessions.
- **Storm control.** A handshake admission queue on the server, and jittered backoff on clients.

### 3.5 HTTP layer

- Advertise only `http/1.1` via ALPN. HTTP/2 would add HPACK tables and per-stream and flow-control state.
- Keep a minimal incremental parser whose state is a few bytes, with strict header-size limits.
- Track only the stream offset where the current response began, and derive everything else.

### 3.6 Timers, tiering and lookup

- Use a hierarchical timing wheel, or bucketed lazy expiry checked on access, so a timer costs a few bits per connection rather than a node each.
- TLS and HTTP use the TCP timer slot; TLS only needs a handshake timeout.
- **Hot/idle tiering.** Active connections get a full working record. Idle connections are frozen into a minimal form and thawed when a packet arrives.

### 3.7 I/O and testing

- **I/O backends.**
  - Start with the in-process simulator.
  - Then AF_XDP: it works over veth in generic mode on a laptop, and allows testing against real Linux clients in network namespaces.
  - DPDK is optional and later.
- **Simulated client swarm.** Clients derive their expected state (ISN, sequence numbers, behavior schedule) from a hash of their 4-tuple and the current time, so a billion simulated clients cost close to zero memory.
- **Interop tests** against `curl`, the Linux kernel stack, and common TLS libraries early and continuously.

## 4. Milestones

1. **Sans-IO TCP core.** Handshake, data, FIN/RST, and a basic RTO, with a deterministic simulator and fuzzing.
2. **Real interop.** AF_XDP over veth, with Linux kernel clients in network namespaces. `curl http://…` works.
3. **Plaintext HTTP/1.1.** Keep-alive, regenerable responses, and offset-addressed retransmission.
4. **Compact connection table and timing wheel.** Measure bytes per connection, with a `const` size assertion.
5. **Simulated client swarm.** Push toward 10–100M connections, and profile cache misses and packets/s per core.
6. **TLS 1.3, steady state.**
   - rustls handshake, then secret extraction and the custom record layer.
   - Fixed-size records with the immutability invariant.
   - Bounded partial-record pool.
   - Re-measure bytes per connection.
7. **Resumption and storms.**
   - Session tickets; compare `psk_dhe_ke` and `psk_ke`.
   - Handshake admission control.
   - Measure time to recover from a simulated mass disconnect.
8. **Tiering.** Idle/active record freezing and thawing.
9. **Optional.**
   - A real large-memory or cloud run.
   - Replacing the rustls handshake to shrink the transient pool.
   - A DPDK backend.

## 5. Background reading

### Protocol specifications

- RFC 9293: Transmission Control Protocol (consolidated TCP spec). https://www.rfc-editor.org/rfc/rfc9293
- RFC 6298: Computing TCP's Retransmission Timer. https://www.rfc-editor.org/rfc/rfc6298
- RFC 7323: TCP Extensions for High Performance (window scale, timestamps). https://www.rfc-editor.org/rfc/rfc7323
- RFC 4987: TCP SYN Flooding Attacks and Common Mitigations (includes SYN cookies). https://www.rfc-editor.org/rfc/rfc4987
- RFC 8446: TLS 1.3 (see §5.3 for the per-record nonce, §4.6.1 for NewSessionTicket, §2.2 for resumption and PSK). https://www.rfc-editor.org/rfc/rfc8446
- RFC 8449: Record Size Limit Extension for TLS. https://www.rfc-editor.org/rfc/rfc8449
- RFC 9112: HTTP/1.1. https://www.rfc-editor.org/rfc/rfc9112

### Scale data points

- MigratoryData, *Scaling to 12 Million Concurrent Connections* (kernel memory per socket, file-descriptor and port tuning). https://migratorydata.com/blog/migratorydata-with-12-million-concurrent-websockets/
- MigratoryData, *12 million concurrent users benchmark*. https://migratorydata.com/blog/websockets-benchmark-12-million-concurrent-users

### Minimal-state transports and stacks

- Shieh, Myers, Sirer, *Trickles: A Stateless Network Stack for Improved Scalability, Resilience, and Flexibility*, NSDI 2005. https://www.usenix.org/legacy/event/nsdi05/tech/full_papers/shieh/shieh_html/index.html
- Jeong et al., *mTCP: A Highly Scalable User-level TCP Stack for Multicore Systems*, NSDI 2014. https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/jeong
- Belay et al., *IX: A Protected Dataplane Operating System for High Throughput and Low Latency*, OSDI 2014. https://www.usenix.org/conference/osdi14/technical-sessions/presentation/belay
- F-Stack (FreeBSD stack on DPDK). https://github.com/F-Stack/f-stack
- smoltcp (Rust, no_std TCP/IP). https://github.com/smoltcp-rs/smoltcp

### Load balancing without per-flow state at the server

- Eisenbud et al., *Maglev: A Fast and Reliable Software Network Load Balancer*, NSDI 2016 (consistent hashing and connection tracking). https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/eisenbud
- Katran (Meta's XDP-based L4 load balancer). https://github.com/facebookincubator/katran

### Implementation building blocks

- rustls, including `Connection::dangerous_extract_secrets()` and `ExtractedSecrets`. https://github.com/rustls/rustls
- quinn / quinn-proto, a reference for sans-IO protocol design. https://github.com/quinn-rs/quinn
- Linux AF_XDP documentation. https://docs.kernel.org/networking/af_xdp.html
- Varghese and Lauck, *Hashed and Hierarchical Timing Wheels: Data Structures for the Efficient Implementation of a Timer Facility*, SOSP 1987.
