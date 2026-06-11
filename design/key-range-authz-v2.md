# Design: per-identity key-range authorization for FoundationDB — v2

**Status:** Draft for upstream review / POC implementation
**Date:** 2026-06-10
**Branch:** `poc/key-range-authz-v2` in the apple/foundationdb checkout
(`/home/pierrez/workspace/just-build-fdb/src`), based on apple `upstream/main` (`72fca11de1`).
**Supersedes (in part):** `design/key-range-authz-v1.md` (v1) on **read-side enforcement
placement**, **SS-reboot durability**, **the cluster-admin identity model**, and **the
simulation/TLS strategy**. Keeps v1's two correct decisions: the **metadata-mutation broadcast**
for policy distribution, and **identity decoupled from `isTrustedPeer`**.
**Reuses (unchanged):** v0 (`design/key-range-authz.md`) — threat model (§2.1), identity model
(§2.2), rationale (§3). Read v0 first; those parts are not restated here.

---

## Feature recap

**Per-identity key-range authorization for FoundationDB**: every client connection carries an
identity (the verified mTLS client-cert CN), and per-identity policies grant Read/Write over key
ranges. Enforcement is authoritative on the server — writes at the CommitProxy, reads at the
StorageServers — so a layer client can be confined to its keyspace without trusting client-side
code. This is a standalone feature, deliberately **not** a revival of tenants/metacluster: no key
prefixing, no metadata cluster, just grants over the existing keyspace. Everything is gated by one
knob (`AUTHZ_ENFORCEMENT_ENABLED`, default **off**) — zero behavior change when disabled.

How it works:

- **Policy storage & distribution.** One row per identity at `\xff/authz/policy/<identity>` (a
  list of range grants). A policy write is recognized at the CommitProxy as a metadata mutation
  and broadcast to every storage server through the existing TLog stream — privatized, tagged to
  all SS tags, applied in version order (the mechanism the deleted tenant map used). No polling,
  no background actors, no new connections; every server converges on the same policy at the same
  commit versions. Proxies rebuild their map from the `txnStateStore` at recovery.
- **Version-correct read checks.** SS-side checks run after `waitForVersion` and after KeySelector
  resolution: the policy map is exact as-of the read version (fail-closed — a revoke denies the
  revoked identity's own in-flight reads) and the check covers the keys actually read. A plain
  map suffices; no versioned data structure.
- **Reboot durability (SS), three legs.** Policy rows persist through the SS mutation log on
  apply; restore from disk before serving reads; a freshly recruited SS one-shot-reads the policy
  at registration (its brand-new broadcast tag cannot see history) and persists it immediately.
- **Bounded state.** `AUTHZ_MAX_IDENTITIES` (default 32, sim-randomized 4–32) caps distinct
  identities, enforced at the proxy before metadata application (`authz_too_many_identities`).
- **Identity in simulation.** Each simulated process is issued one immutable identity string
  (write-once) — forgery and mid-life switches are impossible by construction; no simulated TLS
  handshake.

Status / evidence: ~1,100 lines across 26 files on this branch. Randomized multi-client sim
workload (allow/deny matrix, admin bypass, cap-adaptive grants + overflow rejection) running with
fault injection (machine kills/reboots, random data movement). Simulation caught two real bugs
during hardening (a fresh-recruit durability hole the original tenant-map code also shipped with,
and a wrong-deny window during post-reboot tlog replay — both fixed). 100/100 local seeds;
Joshua ensembles green (1000/1000; a 100k-run ensemble in progress). Remaining before a feature
proposal: read coverage for stream/mapped/watch endpoints, the admin-only `\xff/authz/*` subspace
guard (§2.5), per-role admin identities, production identity derivation + the real-TLS contract
test, and operator UX (fdbcli / special keys).

---

## Addendum (2026-06-11) — decisions taken during the durability/identity/cap increment

User-directed re-scope; these supersede the matching sections below where they differ.

1. **§2.8 superseded (sim TLS strategy).** The trust authority + fake-handshake
   presented-vs-issued check + failure-injection dice + bounded handshake-slot `FlowLock` are
   **dropped for the POC** in favor of the most-KISS model: in simulation, identity is a plain
   **immutable string issued at most once per process** (`ProcessInfo::issueIdentity`, ASSERT on
   re-issue). `Sim2Conn::getPeerCertIdentity()` returns the peer process's issued string directly —
   the X509 mint+parse roundtrip was deleted as tautological (it parsed a cert minted from the very
   string it returned). Forge-resistance is structural: there is no API to present an identity a
   process was not issued, and immutability removes the mid-life-switch hazard. Everything in sim
   shares one address space, so a modeled handshake check defends against an attacker that cannot
   exist there; the real-TLS contract (`AuthzTlsTest`) stays deferred to the feature doc.
2. **Proxies confirmed reboot-proof** (no work needed): policy rows are written to the
   `txnStateStore` on the live path and a freshly recruited proxy rebuilds its map from the
   recovery replay (`initialCommit`) of that store.
3. **SS durability gains a third leg.** Besides persist (`persistAuthzPolicyKeys` in
   `applyPrivateData`) + restore (`restoreDurableState`), a **freshly recruited** SS does a
   one-shot `\xff/authz/policy/*` read at registration (`initAuthzPolicyMap`, the tenant
   `initTenantMap` analog) — its tag only receives broadcasts from its registration version on.
   The fetched rows are **written to storage immediately** (`storage.writeKeyValue`, made durable by
   the new-server commit that follows): the tenant template's `initTenantMap` populated the map
   in-memory only (`insertTenant(..., persist=false)`), so a fresh-then-rebooted SS came back empty
   and wrongly denied. Found by sim (seed 1035 sweep) — the tenant code shipped with this hole.
3b. **§2.3's placement fix for the three existing read checks was pulled INTO this increment**
   (the endpoint-coverage expansion — stream/mapped/watch — stays deferred). The same seed-1035
   sweep proved §2.6's claim that durability and placement compose: an SS that reboots before the
   policy versions are durable restores an (correctly) empty map and replays the mutations from
   `durableVersion+1` — but the v1 entry-placed check consulted the map *before* `waitForVersion`,
   denying granted clients during the replay window. The checks in `getValueQ` / `getKeyValuesQ` /
   `getKeyQ` now run after `waitForVersion` + `findKey` against the resolved range/key (also closing
   the selector-offset bypass for these endpoints); `permission_denied` joined `canReplyWith`.
4. **`AUTHZ_MAX_IDENTITIES` (=32, sim-randomized 4–32 via `randomize && buggify()`).** Enforced at
   the CommitProxy **before** `applyMetadataToCommittedTransactions` — by the time the
   assign-stage pre-pass runs, the batch's metadata has already been applied to the proxy map, the
   `txnStateStore` and the broadcast stream, so a later rejection could not undo the row. Rejection
   error: `authz_too_many_identities` (6006).
5. **Known issue (feeds §2.5, still deferred):** the v1 write-ACL check sits in the assign-stage
   pre-pass, i.e. *after* metadata application — a denied transaction that wrote `\xff/authz/*`
   has already had its policy mutation applied and broadcast. The §2.5 subspace guard must move to
   the same pre-metadata hook the cap check now uses.

---

## 0. Start here (POC orientation)

This is the design for a POC. A fresh instance of Claude is intended to pick this up after a
context reset and start writing code. Read this section, then v1 §1–§3 and v0 §1–§3 for the reused
rationale.

**Where the code lives:** branch `poc/key-range-authz-v2` in the apple/foundationdb checkout at
`/home/pierrez/workspace/just-build-fdb/src`. The superproject at
`/home/pierrez/workspace/just-build-fdb` provides the build container and `just` recipes — see its
`CLAUDE.md` (container-as-a-service, recipe modules under `just/`).

**Build / test workflow** (do NOT trigger a cold FDB build to verify something — cold builds take
hours):

- `just dev up` — idempotent; starts the dev container.
- `just build configure` — first-time CMake. After that, incremental builds are fast.
- `just sim run tests/fast/AuthzKeyRange.toml` — once incremental builds succeed.

**Commit conventions:** the first commit on this branch is this design doc itself, committed
**without GPG signing** (one-off, for context-reset bootstrap — matches v0/v1). Subsequent commits
follow the superproject `CLAUDE.md`: conventional-commits, GPG-signed via Yubikey — wait for the
user to touch the key before assuming `git commit` will complete.

**Note on line numbers:** all `file:line` references below were taken against the v1 branch tree.
This branch is based on a newer `main` (`72fca11de1`); **Stage 0 re-ports v1's plumbing onto this
base and re-validates every hook** before any new code.

**Suggested first move:**

1. Read this doc, then v1 + v0.
2. Stage 0: re-port v1's defensible plumbing (identity through FlowTransport, the shared X509 CN
   extractor, the broadcast in `ApplyMetadataMutation`) onto this base; re-confirm the hook points.
3. Implement Stages 1→6 in order. All data-plane behavior stays gated by `AUTHZ_ENFORCEMENT_ENABLED`
   (default off).
4. Verify with the simulation workloads (§4.6).

---

## 1. Why v2 (what v1's review found)

v1 (`poc/key-range-authz-v1`) shipped the broadcast distribution and the admin-CN decoupling, but a
review plus targeted exploration surfaced concrete gaps. v2 closes them and adds the simulation
fidelity v0/v1 lacked.

1. **Read checks run too early.** v1 checks each SS read *before* `waitForVersion(req.version)` and
   *before* `findKey()` resolves the request's KeySelectors. Two consequences: a **stale-allow
   window** (the SS may not yet have applied the policy as of the read version) and a
   **selector-offset bypass** (the check sees the selector *anchor*, not the *resolved* range a
   selector with an offset actually reads).
2. **Incomplete read surface.** v1 guards only `getValueQ`/`getKeyValuesQ`/`getKeyQ`.
   `getMappedKeyValuesQ` and `getKeyValuesStreamQ` are unguarded — and the mapped path's secondary
   reads go through an internal `readRange` that inherits the loopback (admin) identity, a full
   read bypass.
3. **Reboot loses the policy.** The SS authz map is in-memory only; on restart it comes up empty and
   the log cursor peeks from `durableVersion+1`, so policy mutations at/before the durable version
   are never replayed. Under enforcement the SS would wrongly **deny everything** after reboot.
4. **No write-path bound or subspace guard.** Nothing caps the number of identities, and a non-admin
   granted `W` over a broad range spanning `\xff/authz/*` could rewrite its own policy (escalation).
5. **Coarse cluster identity (accepted for v2).** One shared admin CN ⇒ any server can act as any
   identity — kept for now; per-role admin deferred (§2.7).
6. **Simulation can't prove the security property.** The sim handshake is a `delay()` stub and
   identity is *self-asserted* (`setPresentedIdentity` writes the process's own `simPeerIdentity`),
   so forge-resistance is not tested. (This is the v0 "you cheated" gap.)

**User-set constraints for v2:** plain (unordered) in-memory policy map — **no `VersionedMap`**; a
**`AUTHZ_MAX_IDENTITIES = 32`** cap; **no real OpenSSL handshake in simulation** — instead a
*proper fake* of the TLS boundary that doubles as a failure-injection surface (per
<https://pierrezemb.fr/posts/designing-fakes-that-prove-correctness/>).

---

## 2. Architecture

### 2.1 Threat model & identity
Unchanged from v0 §2.1/§2.2. Identity = the verified mTLS peer cert CN, read server-side at message
deserialization, immune to client forgery. Empty identity (no client cert) → denied. System
metadata (`\xff/…`) is within the authz domain; `ACCESS_SYSTEM_KEYS` stacks with authz.

### 2.2 Policy distribution (kept from v1)
A write to `\xff/authz/policy/<identity>` is a metadata mutation: recognized at the CommitProxy
(`checkSetAuthzPolicyPrefix`/`checkClearAuthzPolicyPrefix` in `ApplyMetadataMutation.cpp`),
privatized to `\xff\xff/authz/policy/*`, tagged to all StorageServers, and applied in version order
in `applyPrivateData`. A freshly recruited proxy/SS replays the full policy from the `txnStateStore`
snapshot (`initialCommit`). Each SS holds a plain `std::unordered_map<std::string, PolicyEntry>`,
bounded by §2.5.

### 2.3 Read enforcement — placement is the fix
**Check *after* `waitForVersion(req.version)` and *after* `findKey()`, against the resolved range.**
This single move closes both v1 read bugs: the map then reflects policy ≥ the read version (no
stale-allow), and the check covers the keys actually read (no selector bypass). Because policy
mutations ride the same version stream as data, `waitForVersion` guarantees the policy as of the
read version is applied; the plain map is therefore security-correct and **fail-closed** — a revoke
within the MVCC window denies the revoked identity's own in-flight reads, which is the desired
behavior. No `VersionedMap` required.

Cover **all `PublicRequestStream` read endpoints** (the external read surface; metrics/split/
checkpoint are private `RequestStream`s behind the trusted-peer fence, and change feeds are a stub
on this fork): `getValueQ`, `getKeyValuesQ`, `getKeyQ`, `getKeyValuesStreamQ` (resolved range up
front + on each loop range-advance), `getMappedKeyValuesQ`, and `watchValueQ` (a watch leaks
key existence). For `getMappedKeyValuesQ`, the first cut **denies mapped reads for non-admin
identities** (the secondary reads bypass the per-handler check); per-mapped-subrange checking is the
follow-up. Centralize on the `ssAuthzCheck` helper and add a sim assertion that every public read
endpoint denies an unauthorized identity, so a future endpoint can't silently skip the gate.

### 2.4 Write enforcement (CommitProxy, kept from v1)
Per-mutation `W` check in the commit pre-pass (`assignMutationsToStorageServers`); deny → reject the
whole transaction with `permission_denied`.

### 2.5 Write-path integrity (new)
Both live in the **live commit pre-pass** — which recovery replay
(`applyMetadataMutations(initialCommit=true)`) never runs, so neither rejects legitimately-saved
rows on restart:

- **`AUTHZ_MAX_IDENTITIES` (=32):** reject a commit that creates a *new* identity beyond the cap;
  updates to an existing identity still succeed. Bounds memory, recovery cost, and makes the linear
  grant scan a non-issue. Surface a dedicated error (`authz_too_many_identities`).
- **Policy-subspace protection:** writes to `\xff/authz/*` require an **admin** identity and are
  never authorizable by an ordinary grant — closes the broad-grant self-escalation hole.

### 2.6 Reboot durability (new)
Mirror the deleted tenant map: add `persistAuthzPolicyKeys`; persist policy rows to the SS mutation
log in `applyPrivateData` (`addMutationToMutationLog`) and **restore them in `restoreDurableState()`
before serving reads**. Template: `bab7637d8^:fdbserver/storageserver.actor.cpp`
(`persistTenantMapKeys`, `insertTenant`/`clearTenants`). Combined with §2.3's check-after-
`waitForVersion`, this removes any fail-open/fail-closed window on reboot.

### 2.7 Cluster-admin identity (single `AUTHZ_INITIAL_ADMIN_CN`)
Cluster-internal traffic (recovery, DataDistribution, ratekeeper, backup, DR, loopback self-reads)
bypasses authz by presenting the **single admin CN** (`AUTHZ_INITIAL_ADMIN_CN`); the check is a CN
equality test, keyed on the CN we already extract — **no extra cert-field plumbing**. Check order:
knob-off → allow; identity == adminCN → allow; empty → deny; else policy lookup.

**Decided:** do *not* add `AUTHZ_PRIVILEGED_PEERS` / the `--tls-verify-peers` grammar. It conflates
handshake-trust (who may connect) with data-authz (what an identity may touch), is a coarse
all-or-nothing bypass keyed on a fuzzy CN prefix (one CA mis-issue ⇒ full access), and lives outside
the policy model. Accepted limitation: one shared admin cert ⇒ any server can act as any identity
(cluster-internal cross-role is out of the v0 threat model). **Deferred** (§6): per-role admin
identities as *distributed policy data* — an admin set at `\xff/authz/admin/<cn>` broadcast like
policy rows (auditable, individually + atomically revocable, keyed on the CN), not a knob.

### 2.8 A verified TLS fake for simulation (the centerpiece)
Per "designing fakes that prove correctness": fake the boundary you don't own
(`IConnection::accept/connectHandshake` + `getPeerCertIdentity`), model only what the code touches
(verified identity; handshake outcome/latency; the bounded handshake resource), and make the fake a
seeded failure-injection surface. **No real OpenSSL handshake in sim.**

- **Identity becomes *issued*, not *asserted*.** Move identity ownership from workload
  self-assertion (`AuthzKeyRangeWorkload::setPresentedIdentity`) to a **sim trust authority on
  `ISimulator`** that issues each process a cert spec (CN + optional O/OU/SAN) at setup. A process
  is *configured* to present an identity, but the **fake handshake checks presented-vs-issued and
  fails on a mismatch** — a forged/un-issued identity cannot connect, mirroring the real "non-CA
  cert → handshake fails." Remove `setPresentedIdentity`.
- **Failure-injection surface.** `accept/connectHandshake` stop being `delay()` stubs and roll
  seeded dice (à la `rollRandomClose`) for: forged/untrusted rejection, hang/slow (→
  `CONNECTION_MONITOR_TIMEOUT` paths), and contention on a **bounded sim handshake-slot resource**
  (a sim-wide `FlowLock`, knob-controlled) modeling production's global `handshakeLock` + 64-thread
  `sslHandshakerPool` (`Net2.cpp`).
- **Production local-identity + unify.** Derive the local process CN from its *own* loaded cert
  (`LoadedTLSConfig::getCertificateBytes` → `SSL_CTX_get0_certificate` →
  `extractCommonNameFromX509`) at `fdbserver.cpp` after `initTLS()`, then `setLocalIdentity`. Drive
  sim and prod through the same derivation.
- **Verified equivalence (real side).** Extend `fdbrpc/tests/AuthzTlsTest.cpp` (real OpenSSL, real
  CA) to assert the contract the fake models: add `peerIdentity` to `SessionInfo`, assert
  `currentDeliveryPeerIdentity == issued CN`, and add a **forged-cert case** (client cert signed by
  a non-trusted CA → handshake fails / empty identity). This is what makes the sim fake load-bearing.

---

## 3. Rationale (v2-specific)

- **Why placement, not `VersionedMap`.** `waitForVersion` already guarantees the SS has applied the
  policy as of the read version; checking after it makes the plain map exact-enough and fail-closed.
  A `VersionedMap` would add memory/complexity and actually let revoked in-flight reads continue for
  the MVCC window — worse for a security primitive. (User chose the plain map.)
- **Why a 32-identity cap.** Bounds the broadcast/replication and recovery state (the tenant-map
  scaling ceiling), keeps the per-read linear grant scan trivial, and makes the plain map a
  non-issue. A first feature does not need unbounded identities.
- **Why a *fake* TLS boundary, not a real sim handshake.** A real handshake reproduces OpenSSL
  (the anti-pattern); the code only touches the *verified identity* and the *handshake outcome*.
  A proper fake models exactly those and proves forge-resistance via an issued-vs-presented check.
  `AuthzTlsTest` (real OpenSSL) is the contract that keeps the fake honest.
- **Why a single admin CN, not the privileged-peers grammar.** Reusing `--tls-verify-peers` for an
  authz bypass conflates two trust layers, is coarse (a prefix match = god mode), sits outside the
  policy model, and needs O/OU/SAN cert-field plumbing the CN path doesn't. Per-role admin, when
  needed, belongs *in* the policy (`\xff/authz/admin/<cn>`), not in a TLS-config knob.

---

## 4. Implementation plan

### 4.1 Stages (each independently reviewable; behavior gated by `AUTHZ_ENFORCEMENT_ENABLED`)
| Stage | Scope | Behavior change |
|---|---|---|
| 0 | Re-port v1 plumbing onto this base (`72fca11de1`); re-validate hooks. | None |
| 1 | Read enforcement: complete public-endpoint coverage; check after `waitForVersion`+`findKey` against the resolved range; plain unordered map. | None until knob on |
| 2 | Write-path integrity: `AUTHZ_MAX_IDENTITIES`=32 cap + `\xff/authz/*` admin-only, in the commit pre-pass. | None until knob on |
| 3 | Reboot durability: `persistAuthzPolicyKeys` + restore in `restoreDurableState`. | None |
| 4 | Cluster-admin identity: single `AUTHZ_INITIAL_ADMIN_CN` (CN-equality bypass). | None until knob on |
| 5 | Verified TLS fake: sim trust authority (issued identity), fake handshake with presented-vs-issued + failure injection + bounded handshake slots; production local-identity; `AuthzTlsTest` contract. | Sim/test only |
| 6 | Workloads: enforcement, forge-resistance, admin-bypass, reboot durability. Flip the knob. | Authz live (opt-in) |

### 4.2 Knobs
| Knob | Default | Purpose |
|---|---|---|
| `AUTHZ_ENFORCEMENT_ENABLED` | `false` | Master switch; off → allow. |
| `AUTHZ_INITIAL_ADMIN_CN` | `""` | Cluster-internal/admin identity (cert CN); cluster/backup/DR present this — CN-equality bypass. |
| `AUTHZ_MAX_IDENTITIES` | `32` | Cap on distinct policy identities. |
| sim handshake failure-rate | (sim) | Injects TLS handshake failures. |

### 4.3 Critical files
- Read enforcement / persistence / SS apply: `fdbserver/storageserver/storageserver.actor.cpp`
- Broadcast + recovery replay: `fdbserver/logsystem/ApplyMetadataMutation.cpp`
- Write pre-pass (cap + subspace): `fdbserver/commitproxy/CommitProxyServer.cpp`,
  `fdbserver/commitproxy/ProxyCommitData.h`
- Policy types/keys: `fdbclient/include/fdbclient/AuthzPolicy.h`, `fdbclient/SystemData.cpp`/`.h`
- Identity plumbing (CN): `fdbrpc/FlowTransport.cpp`/`.h`,
  `fdbrpc/include/fdbrpc/TimedRequest.h`, `flow/include/flow/IConnection.h`
- Sim TLS fake + trust authority: `fdbrpc/sim2.cpp`, `fdbrpc/simulator.h`,
  `fdbrpc/include/fdbrpc/SimulatorProcessInfo.h`, `fdbserver/SimulatedCluster.cpp`
- Cert minting (CN/O/OU/SAN) + shared extractor: `flow/MkCert.cpp`/`.h`,
  `flow/include/flow/X509Identity.h`
- Production local-identity: `fdbserver/fdbserver.cpp` (after `initTLS`)
- Verified-equivalence contract: `fdbrpc/tests/AuthzTlsTest.cpp`
- Knobs: `fdbserver/core/ServerKnobs.cpp`, `fdbserver/core/include/fdbserver/core/Knobs.h`
- Workloads/tests: `fdbserver/workloads/AuthzKeyRangeWorkload.cpp`, `tests/fast/AuthzKeyRange.toml`

### 4.4 Code reuse
| Need | Reuse from |
|---|---|
| Metadata-broadcast template | `bab7637d8^:fdbserver/ApplyMetadataMutation.cpp` (tenant handlers); model all-SS tagging on `checkSetServerTagsPrefix` |
| SS-local persist + restore | `bab7637d8^:fdbserver/storageserver.actor.cpp` (`persistTenantMapKeys`, `insertTenant`/`clearTenants`) |
| Shared X509 CN extractor | `flow/X509Identity.h` `extractCommonNameFromX509` (production + sim) |
| Real-TLS contract harness | `fdbrpc/tests/AuthzTlsTest.cpp` |
| `permission_denied` (6000) | `flow/include/flow/error_definitions.h` |

### 4.6 Verification (sim-driven)
1. `just dev up`; incremental build.
2. `just sim run tests/fast/AuthzKeyRange.toml` — enforcement allow/deny; **zero `SevError`**.
3. Forge-resistance seed: a process presenting an un-issued identity → handshake fails / denied.
4. Admin seed: admin-CN bypass vs layer-CN enforced.
5. Reboot seed: `forceSSL` + cluster reboot → recovers, enforcement correct, no fail-open,
   policy restored from `persistAuthzPolicyKeys`.
6. Cap: a 33rd identity is rejected; subspace: a non-admin write to `\xff/authz/*` is denied.
7. Real-side contract: `AuthzTlsTest` asserts `identity == issued CN` and rejects a forged cert.
8. Re-run several seeds (deterministic with `forceSSL`).

---

## 5. Risks
| # | Risk | Mitigation |
|---|---|---|
| 1 | `ApplyMetadataMutation`/`applyPrivateData` are recovery-critical, wide recompile blast radius | Copy proven tenant handlers; gate behind the enforcement knob; narrow headers |
| 2 | Mapped reads (`getMappedKeyValuesQ`) bypass per-handler checks | First cut denies non-admin mapped reads; per-subrange checks as follow-up |
| 3 | Sim fake diverges from real TLS | `AuthzTlsTest` (real OpenSSL) is the contract the fake is checked against |
| 4 | Single admin CN coarse (any server = any identity) | Accepted for v2 (out of threat model); per-role admin via distributed `\xff/authz/admin/<cn>` deferred |
| 5 | Client `\xff` reads under a non-admin identity | Grant single-key R, or document; system keyspace is admin-only |

---

## 6. Out of scope (deferred)
Per-role admin identities as distributed policy data (`\xff/authz/admin/<cn>`); `AUTHZ_PRIVILEGED_PEERS`
/ the `--tls-verify-peers` grammar (rejected — wrong layer, coarse, outside the policy model); real
OpenSSL handshake in sim (the fake is deliberate); SAN-fallback extraction; per-mapped-subrange authz
(conservative deny first); special-keys `\xff\xff/management/authz/` subspace + fdbcli; binary search
in the grant lookup; per-transaction signed sub-identity for in-layer customer isolation (v0 §6).

## 7. References
- v1 design: `design/key-range-authz-v1.md` (broadcast, admin-CN decoupling).
- v0 design: `design/key-range-authz.md` (threat model, identity, rationale, alternatives).
- v0 POC report: `design/key-range-authz-poc-report.md` (the `isTrustedPeer` coupling post-mortem).
- Tenant/metacluster deletion (templates): PR #12583, commit `bab7637d8`.
- Fakes philosophy: <https://pierrezemb.fr/posts/designing-fakes-that-prove-correctness/>.
