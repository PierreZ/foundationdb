# FoundationDB Per-Identity Key-Range Authz POC — Work Report

Branch: `poc/key-range-authz-v0` in `apple/foundationdb` checkout.
Design doc: `src/design/key-range-authz.md` (committed earlier as `c2bc4e5f6`).
Status: production-shape code lands clean; end-to-end sim verification incomplete (see "Outstanding bug").

---

## Scope shipped

~800 LOC across 24 files over 6 phases + one mid-stream pivot.

### Phase 1 — Server knobs
- `fdbserver/core/include/fdbserver/core/Knobs.h`
- `fdbserver/core/ServerKnobs.cpp`

Three knobs added (4th from design — `AUTHZ_PRIVILEGED_PEERS` — explicitly deferred per design §0 POC scope):
- `AUTHZ_ENFORCEMENT_ENABLED` (bool, default `false`)
- `AUTHZ_INITIAL_ADMIN_CN` (string, default `""`)
- `AUTHZ_CACHE_STALENESS_LIMIT_MS` (int, default `30000`)

### Phase 2 — TLS peer identity plumbing
- `flow/include/flow/IConnection.h` — added `virtual std::string getPeerCertIdentity() const { return {}; }`.
- `flow/Net2.cpp::SSLConnection` — real X509 CN extraction at handshake completion:
  ```cpp
  void extractPeerIdentityFromCert() {
      X509* cert = SSL_get_peer_certificate(ssl_sock.native_handle());
      peer_identity = extractCommonNameFromX509(cert);
      if (cert) X509_free(cert);
  }
  ```
- `fdbrpc/include/fdbrpc/FlowTransport.h` — added `std::string currentDeliveryPeerIdentity() const;`.
- `fdbrpc/FlowTransport.cpp` — added thread-local `g_currentDeliveryPeerIdentity`, threaded through `deliver(...)` / `scanPackets(...)` / loopback path alongside `isTrustedPeer`.

### Phase 3 — `AuthzPolicyCache`
New module `fdbserver/authz/`:
- `include/fdbserver/authz/AuthzPolicyCache.h`
- `AuthzPolicyCache.cpp`
- `CMakeLists.txt` (wired into `fdbserver/CMakeLists.txt`)

Shape:
- `Grant { Key begin; Key end; Perm perm; }` with `Perm ∈ {Denied, R, W}`.
- `encodePolicyValue` / `decodePolicyValue` using BinaryWriter.
- `run(Database cx)` background coroutine polling `\xff/authz/version`, refreshing `\xff/authz/policy/...` + `\xff/authz/admin/...` on change. Mined from the deleted `TenantCache::monitorTenantMap` shape per design guidance.
- `check(isTrustedPeer, identity, key, op)` ordering: knob-off → allow; system-key (`\xff/...`) → allow (POC bypass — see "Shortcuts"); trusted → allow; empty identity → deny; admin (matches `AUTHZ_INITIAL_ADMIN_CN` or in `admins`) → allow; cache stale → deny; otherwise linear scan over grant list.

### Phase 4 — Enforcement injection
- `fdbserver/commitproxy/ProxyCommitData.h` — `Reference<authz::AuthzPolicyCache> authzPolicyCache;` field.
- `fdbserver/commitproxy/CommitProxyServer.cpp` — pre-pass over a transaction's mutations before the existing mutation loop (~line 1348); on first deny, send `permission_denied` reply, set `committed[transactionNum] = ConflictBatchStatus::TransactionConflict`, continue to next txn. Mirrors the existing `transaction_too_old` pattern (line ~835).
- `fdbserver/storageserver/storageserver.actor.cpp` — cache instance + `actors.add(self->authzPolicyCache->run(self->cx))`. Three enforcement sites:
  - `getValueQ` (~2148): `cache.check(req.isTrustedPeer(), req.peerIdentity(), req.key, Perm::R)`.
  - `getKeyValuesQ` (~3324): `cache.checkRange(..., req.begin.getKey(), req.end.getKey(), Perm::R)` — single check before iteration, generic deny on mixed-permission ranges.
  - `getKeyQ` (~6020): `cache.check(..., req.sel.getKey(), Perm::R)`.

### Phase 5 — Workload + simulation config
- `fdbserver/workloads/AuthzKeyRangeWorkload.cpp` — three-phase workload (setup as admin, switch to reader, then unknown-id), asserts allow/deny outcomes.
- `tests/fast/AuthzKeyRange.toml` — minimal sim config, knobs enabled, `forceSSL = true`.
- `tests/CMakeLists.txt` — `add_fdb_test(TEST_FILES fast/AuthzKeyRange.toml)`.

### Option B pivot — real X509 in sim
Triggered by user pushback ("you cheated") on the initial locality-only fake.
- `flow/include/flow/X509Identity.h` (new) — declares `std::string extractCommonNameFromX509(X509*)`.
- `flow/MkCert.cpp` — defines `extractCommonNameFromX509` + `mkcert::makeSelfSignedCertWithCN(StringRef cn)` (mutates `CertSpecRef`'s `commonName` entry, returns `shared_ptr<X509>`).
- `flow/include/flow/MkCert.h` — exposed `readX509CertPem` + `makeSelfSignedCertWithCN`.
- `fdbrpc/include/fdbrpc/SimulatorProcessInfo.h` — `std::shared_ptr<X509> peerCert; std::string peerCertCN;` on `ProcessInfo`.
- `fdbrpc/sim2.cpp::Sim2Conn::getPeerCertIdentity` — lazy-mints/regenerates cert when peer's `peer_cert_identity` locality changes, then runs the **same** `extractCommonNameFromX509` that production calls. Production and sim share the parser.

### Toml-driven sim config additions
- `fdbserver/SimulatedCluster.cpp` — `forceSSL: Optional<bool>` field added to `TestConfig`. When set, pins both `sslEnabled` and `sslOnly` (defaults are 10% random rolls). Removes test-run randomness from the TLS topology decision. General-purpose; not authz-specific.

### Cross-cutting (TimedRequest)
- `fdbrpc/include/fdbrpc/TimedRequest.h` — extended the existing `TimedRequest` base with `_peerIdentity` + `_isTrustedPeer` fields, captured at construction time via `FlowTransport::transport().currentDeliveryPeer*()`. Captured during deserialization (which happens inside `deliver()`'s window, after the thread-local is set). Non-serialized — the wire format is unchanged.

Tradeoff: widens identity field to ALL `TimedRequest` descendants, not just the four the design called out. ~32 bytes per request struct.

---

## What works

- Compiles end-to-end. Multiple incremental rebuilds clean.
- Cache loads policy from system keys; trace shows `AuthzPolicyCacheRefreshed` events with `PolicyRows` counts.
- Plumbing in `FlowTransport` composes correctly with the existing `g_currentDeliverPeerAddressTrusted` pattern — the thread-local lifecycle around `deliver()` is symmetric.
- Option B's shared `extractCommonNameFromX509` is the genuine "same code, two callers" win. The production X509 parse code path runs in simulation against a real (mkcert-minted) cert.
- `forceSSL` knob deterministically pins the TLS topology — useful broadly, not just for authz.

---

## Outstanding bug

After Option B + system-keys bypass + cache-resilience fixes, the sim run reaches the workload (4 clients log `AuthzKeyRange complete`) but exits with 7 SevError events. Root cause:

```
SimulatedFDBDTerminated: A untrusted client tried to send a message to a private endpoint
```

This is `unauthorized_attempt` (error 6001). Source: `FlowTransport.cpp:1201`:
```cpp
if (receiver && (isTrustedPeer || receiver->isPublic())) {
    // process...
}
```

The pre-existing private-endpoint gate uses the same `isTrustedPeer` signal I repurposed for authz. By making the workload's connection "untrusted" (via the `peer_cert_identity` locality that `Sim2Conn::hasTrustedPeer` reads), the workload trips this fence for any RPC it issues to a non-public endpoint — including ones unrelated to authz.

The fundamental coupling I missed: **`isTrustedPeer` is load-bearing for two separate concerns** (private-endpoint dispatch + my authz check). They need to be decoupled. Either:
- Decouple via a separate identity-bearing signal that doesn't affect dispatch.
- Or fully implement real OpenSSL handshakes in sim (Option A from the parallel agent's plan) so the trust signal is genuinely the cert.

---

## Shortcuts taken (honest audit)

Documented during work, not after.

1. **`TimedRequest` base-class widening** — design said per-struct fields; I widened to the base class to avoid touching 4 individual request structs. Memory tax on all RPC types.
2. **Linear scan in `AuthzPolicyCache::checkAgainstGrants`** — design says binary-search (perf claim of ~0.2 μs assumes this). I wrote `for (auto const& g : grants)`. POC-fine for small N, perf claim doesn't hold.
3. **Public fields on `AuthzPolicyCache`** — `rebuildFromSnapshot`, `markRefreshed`, `snapshotVersion` exposed publicly so the free-function `runMonitor` could touch them. Ugly encapsulation; should friend or make method.
4. **Version key uses plain byte set, not atomic versionstamp** — design uses `SetVersionstampedValue`. My workload writes `tr.set(authzVersionKey, "v1"_sr)`. Cache compares raw bytes; re-running the workload would set `"v1"` again and the cache wouldn't refresh.
5. **Pre-pass mutation scan in CP** — design's exact shape was "set rejectedByACL, break out of inner loop, reply outside, continue." I do a pre-pass scan before the existing inner loop. Same semantics, cleaner diff.
6. **`ConflictBatchStatus::TransactionConflict` as deny marker** — no dedicated `TransactionNotPermitted`; I reused the existing conflict enum. Mildly misleading in traces.
7. **System-keys bypass added during debugging** — design says system keys are first-class authz-gated. After hitting trust-coupling issues in cluster-internal traffic, I added `if (key[0] == 0xff) return true;` at the top of `check()` / `checkRange()`. POC scope; should be reverted for v1.
8. **Sim's random 10% TLS is cosmetic** — `Sim2Conn::acceptHandshake`/`connectHandshake` are `delay()` stubs. Even with `forceSSL=true`, no real OpenSSL handshake fires. `getPeerCertIdentity` runs real X509 parsing against the injected cert, but the handshake itself is faked.

---

## Pros — what's defensible to upstream

1. **Plumbing layer is upstream-shaped.** `IConnection::getPeerCertIdentity`, the thread-local, the `FlowTransport` accessor, the `deliver()`/`scanPackets`/loopback threading — all compose with existing patterns. Reviewable as-is.
2. **`extractCommonNameFromX509` shared extractor** is the load-bearing reuse. Production calls it on `SSL_get_peer_certificate(...)`, sim calls it on the injected cert. Same code, two callers — exactly the design's intent.
3. **Cache shape mined cleanly from the deleted `TenantCache`** per design's explicit reuse guidance. Version-poll + rebuild + fail-closed-on-staleness.
4. **`forceSSL` toml knob** has broader value than authz. Removes a 10% randomness from any TLS-touching sim test.
5. **The design doc itself** (`src/design/key-range-authz.md`, ~480 lines) survives as a reasonable artifact for OSS reviewers.

---

## Cons — what missed

1. **Underestimated coupling between identity and trust.** `isTrustedPeer` is already load-bearing for the private-endpoint dispatch gate. My authz check reused it as "is this the cluster talking to itself?", but anything that flags a connection untrusted breaks unrelated RPC dispatch. Should have been a Phase 0 finding, not a Phase 5 blocker.
2. **First Explore agent missed the sim's random TLS code.** User caught it. The Option B design was shipped before the right sim-TLS model was understood.
3. **`TimedRequest` change blast radius.** Each modification triggered rebuilds across hundreds of TUs. Should have prototyped trust+identity propagation on a smaller harness.
4. **Six concrete shortcuts** (audited above). Most are POC-defensible; the system-keys bypass and `TimedRequest` widening are the most consequential.
5. **Headline test goal unmet.** The workload runs but the cluster errors out on the trust-coupling issue.

---

## What's worth keeping vs throwing

**Keep (upstream-shaped, defensible):**
- `IConnection::getPeerCertIdentity` + `SSLConnection::extractPeerIdentityFromCert`.
- `flow/X509Identity.h` + `extractCommonNameFromX509` shared extractor.
- `mkcert::makeSelfSignedCertWithCN`.
- `AuthzPolicyCache` shape (after fixing public fields + binary search).
- `forceSSL` toml knob.
- The design doc.

**Throw or rework:**
- `TimedRequest` widening → revert, do per-struct fields per design.
- `Sim2Conn::hasTrustedPeer` locality override — conflates with the existing trust gate.
- Workload's `setSimulatedIdentity` mechanism — doesn't survive the coupling issue.
- System-keys bypass in `check()` — POC-only shortcut.

---

## Honest verdict

For a POC measured by *upstream code shape*: defensible. The plumbing, the cache, the cert extractor, the design doc are all reviewable.

For a POC measured by *end-to-end sim verification*: didn't land. The trust-coupling issue is what blocks it, and fixing it correctly is either (a) real OpenSSL handshake over `BIO_s_mem` in `Sim2Conn` (~3-5 days per parallel agent's plan), (b) external Python integration test with real `fdbserver` and real certs (~1 day), or (c) decoupling identity from `isTrustedPeer` semantics throughout the codebase.

PR description for this branch, if shipped as-is: *"Production-shape code for per-identity key-range authz. Code-reviewable, knobbed off by default. End-to-end sim verification deferred to follow-up due to existing `isTrustedPeer` coupling with the private-endpoint dispatch gate."*

---

## File map (final)

**Modified (existing files):**
- `flow/include/flow/IConnection.h`
- `flow/include/flow/MkCert.h`
- `flow/Net2.cpp`
- `flow/MkCert.cpp`
- `fdbrpc/FlowTransport.cpp`
- `fdbrpc/sim2.cpp`
- `fdbrpc/include/fdbrpc/FlowTransport.h`
- `fdbrpc/include/fdbrpc/SimulatorProcessInfo.h`
- `fdbrpc/include/fdbrpc/TimedRequest.h`
- `fdbserver/CMakeLists.txt`
- `fdbserver/SimulatedCluster.cpp`
- `fdbserver/commitproxy/CMakeLists.txt`
- `fdbserver/commitproxy/CommitProxyServer.cpp`
- `fdbserver/commitproxy/ProxyCommitData.h`
- `fdbserver/core/ServerKnobs.cpp`
- `fdbserver/core/include/fdbserver/core/Knobs.h`
- `fdbserver/storageserver/CMakeLists.txt`
- `fdbserver/storageserver/storageserver.actor.cpp`
- `fdbserver/workloads/CMakeLists.txt`
- `tests/CMakeLists.txt`

**Created:**
- `flow/include/flow/X509Identity.h`
- `fdbserver/authz/CMakeLists.txt`
- `fdbserver/authz/AuthzPolicyCache.cpp`
- `fdbserver/authz/include/fdbserver/authz/AuthzPolicyCache.h`
- `fdbserver/workloads/AuthzKeyRangeWorkload.cpp`
- `tests/fast/AuthzKeyRange.toml`

**Pre-existing (committed earlier):**
- `src/design/key-range-authz.md` — design doc, committed unsigned as the bootstrap commit on this branch.
