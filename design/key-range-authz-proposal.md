# Design: Per-Identity Key-Range Authorization for FoundationDB

**Status:** Draft — for upstream review
**Author:** Pierre Zemb
**Date:** 2026-06-15
**Target:** apple/foundationdb (`upstream/main` @ `72fca11de1`)
**Reference POC:** branch `poc/key-range-authz-v2`
**Validation:** 30,000 / 30,000 Joshua simulation runs passed, 0 failures (`fail_fast` on)

> This document follows FoundationDB's own design-doc template
> (`design/design-doc-template.md`). It is a **design proposal backed by a working
> proof-of-concept** (the reference branch above), submitted to gather upstream feedback
> before the remaining work is completed. The implementation is proposed for upstream as
> **three independently reviewable MRs** — (1) simulation TLS + identity, (2) the core
> authorization feature, (3) `fdbcli` + management subspace — see *Rollout/Migration →
> Delivery plan*. It is **not** proposed for merge as-is.

---

## Objective

Add an **authorization boundary inside a FoundationDB cluster**: every client connection
carries a verified identity (its mTLS client-certificate Common Name), and an operator grants
each identity **Read/Write permission over explicit key ranges**, enforced **authoritatively
on the server** — writes at the CommitProxy, reads at the StorageServers. This lets a layer
confine its clients to a slice of the keyspace **without trusting client-side code**, while
leaving the key layout untouched and costing nothing when not enabled.

---

## Background

FoundationDB authenticates *who may connect* (TLS), but once a connection is established there
is **no boundary on what it may touch**: anyone holding the cluster file can read and write the
entire keyspace. Authorization is effectively all-or-nothing at the cluster boundary.

This is a real gap for **layers** — services built on FDB that serve many of their own
tenants/customers out of one shared cluster. A representative use case: a layer wants client A
confined to `["a", "b")` and client B to `["b", "c")`. Today the only enforcement point is the
layer's own client-side code; anyone who obtains the cluster file (or runs a buggy/compromised
layer build) bypasses it. There is no server-side floor to fall back on.

This proposal deliberately keeps the key layout untouched: an identity is granted access to
ranges of the *existing* keyspace — no key prefixing, no re-import. Authorization is an
**unbundled primitive** placed beside the data, not a property of how keys are stored.
FoundationDB previously shipped tenants + metacluster, since removed upstream (PR #12583,
commit `bab7637d8`); that code is reused here purely as an implementation **template** — its
metadata-broadcast and per-server persistence mechanisms are well-suited to distributing policy
(see *Detailed Design*).

### Defined terms

- **Identity** — the **Common Name (CN)** taken from the **Subject** of the connection's
  verified mTLS client certificate (the `commonName` component of the X.509 Subject
  Distinguished Name, OID 2.5.4.3), determined server-side. A connection with no client
  certificate has the *empty* identity. The `subjectAltName` (SAN) is not consulted in the POC
  (deferred).
- **Grant** — a `(key range, permission)` pair. Permission is `R` or `W`; `W` implies `R`.
- **PolicyEntry / policy** — the set of grants for one identity.
- **Policy map** — the in-memory `identity → PolicyEntry` map each server holds and consults on
  the hot path.
- **Admin identity** — a single configured CN (`AUTHZ_INITIAL_ADMIN_CN`) that bypasses checks;
  used by cluster-internal traffic.

---

## Requirements

The solution must satisfy the following. Each is phrased so it is answerable whether the system
meets it; the *Testing Considerations* section maps each to a simulation check.

- **R1 — Server-authoritative.** Whether a request is allowed is decided by the server from the
  connection's verified identity, never from client-supplied request data. *Met iff* a client
  cannot widen its access by tampering with requests.
- **R2 — Per-identity key-range Read/Write grants.** An operator can grant an identity `R`
  and/or `W` over an arbitrary range `[begin, end)`. *Met iff* operations inside a grant
  succeed and operations outside every grant are denied.
- **R3 — No key-layout change.** Adopting the feature requires no data migration and no key
  prefixing; it adds only system metadata. *Met iff* existing keys are untouched and the core
  adds only the `\xff/authz/policy/*` system range.
- **R4 — Opt-in, default-off no-op.** With `AUTHZ_ENFORCEMENT_ENABLED=false` (default),
  behavior and data-path cost are identical to today. *Met iff* default test ensembles are
  unaffected.
- **R5 — Version-correct & fail-closed.** A read at version `V` is authorized against the
  policy as of `V`; a revoke that commits at version `W` denies the revoked identity from `W`
  onward, including its own in-flight reads. *Met iff* a revoke-during-read seed denies after
  the revoke version.
- **R6 — Bounded state.** The number of distinct identities is capped
  (`AUTHZ_MAX_IDENTITIES`); exceeding it is rejected explicitly rather than silently degrading.
  *Met iff* the cap+1'th identity is rejected with a dedicated error.
- **R7 — Durable across faults.** Policy survives process reboots, cluster recovery, and fresh
  server recruitment with no fail-open and no spurious-deny window. *Met iff* enforcement stays
  correct under injected kills/reboots.

### Non-requirements (out of scope)

- Per-customer isolation *inside* a single layer identity (the layer's responsibility, like a
  single Postgres role; a per-transaction signed sub-identity is sketched in *Rollout*).
- Defense against stolen credentials (a leaked key is the operator's problem, as a leaked
  cluster file is today).
- Cluster-internal cross-role isolation (servers trust each other; see the single admin
  identity).
- Gating the cluster management/administrative API.
- JWT/HMAC bearer-token machinery.

---

## Design Overview

The feature reuses mechanisms FoundationDB already trusts: policy is **distributed the way the
deleted tenant map was** (metadata-mutation broadcast), **persisted the way the tenant map
was** (per-server local store), and **recovered from the `txnStateStore`** like all system
metadata. Nothing polls, nothing opens new connections, and no background monitor is added.

The authoritative policy is ordinary committed data at `\xff/authz/policy/<identity>`. Every
CommitProxy, the Resolver, and every StorageServer additionally keeps an **in-memory policy
map**, kept current by broadcasting each policy change to all of them in version order. Reads
are checked at the StorageServer (after the read version and key-selectors resolve); writes are
checked at the CommitProxy (before resolution).

```
WRITE / CONTROL PATH  (operator sets or clears a policy)
  admin client
    │  set \xff/authz/policy/<id> = PolicyEntry      (or clear over the range)
    ▼
  CommitProxy ── recognize as a metadata mutation (checkSetAuthzPolicyPrefix)
    ├─ update its in-memory policy map               (used for write-side checks)
    ├─ write the txnStateStore                       (recovery-durable copy)
    └─ privatize + tag to ALL storage servers ──► TLog ──► every StorageServer
                                                            ├─ applyPrivateData (version order)
                                                            ├─ update in-memory policy map
                                                            └─ persist to persistAuthzPolicyKeys (on disk)

READ PATH   (enforced at the StorageServer)
  client ─ get / getRange / getKey ─► SS: waitForVersion ─► findKey ─► ssAuthzCheck(map)
                                                                         └─► allow │ permission_denied

WRITE PATH  (enforced at the CommitProxy, before resolution)
  client ─ commit ─► CommitProxy: per-mutation W check  (+ identity-cap check)
                                   └─► allow │ permission_denied │ authz_too_many_identities
```

---

## Detailed Design

### Identity

A request's identity is the **Common Name (CN) from the Subject of the verified mTLS client
certificate**, extracted **server-side at message deserialization** — never read from the
request body. Concretely, the shared helper `extractCommonNameFromX509` (`flow/X509Identity.h`)
calls `X509_get_subject_name()` then `X509_NAME_get_text_by_NID(name, NID_commonName, …)` on
the peer's verified cert (`flow/MkCert.cpp`; invoked from the handshake in `flow/Net2.cpp`).
The `subjectAltName` (SAN) is not consulted in the POC (a SAN fallback is deferred). The
transport stamps this identity onto each delivered request; handlers read it back. A connection
with **no client certificate yields the empty identity, which is always denied** under
enforcement. Same-process (loopback) traffic carries no certificate and falls back to the
process's *own* loaded identity, so a server's self-reads are treated as the cluster identity
(below) rather than denied. *(Plumbing: `fdbrpc/FlowTransport.{h,cpp}`, `TimedRequest.h`,
`flow/IConnection.h`; CN extraction: `flow/X509Identity.h`, `flow/MkCert.cpp`,
`flow/Net2.cpp`.)*

### Policy data model

A policy is **one row per identity**, value = a serialized list of range grants. The types
(`fdbclient/include/fdbclient/AuthzPolicy.h`) are deliberately small (no heavy includes) to
limit recompile blast radius:

```cpp
namespace authz {
enum class Perm : uint8_t { Denied = 0, R = 1, W = 2 };          // W implies R
struct Grant      { Key begin; Key end; uint8_t perm; };          // [begin, end) -> perm
struct PolicyEntry{ std::vector<Grant> grants;
                    bool allows(KeyRef begin, KeyRef end, Perm op) const; };  // linear scan
//   1. adminCN non-empty && identity == adminCN -> allow   (cluster-internal)
//   2. identity empty (no client cert)          -> deny
//   3. identity has no policy row               -> deny
//   4. otherwise                                -> entry.allows(begin, end, op)
bool checkAuthorized(std::map<std::string,PolicyEntry> const&, std::string adminCN,
                     std::string identity, KeyRef begin, KeyRef end, Perm op);
}
```

Two properties: **default-deny** (absence of a grant or identity denies — no implicit access),
and **whole-range coverage** (a single grant must fully cover the requested range; the POC does
not stitch a request across multiple grants). Whole-range coverage keeps the check a trivial
linear scan, which is fine at the identity ceiling below; range-stitching / binary search is a
later optimization.

### Storage structures: where the policy lives, how it is updated, and why it is replicated rather than sharded

The policy exists in **four representations**, each with a distinct job:

| Representation | Where | Purpose | Updated by |
|---|---|---|---|
| **Authoritative rows** | committed KVs at `\xff/authz/policy/<identity>` | durable source of truth, replicated/stored like any system key | the operator's set/clear commit |
| **In-memory policy map** | `std::map<std::string, PolicyEntry>` on every CommitProxy (`ProxyCommitData.h:229`), the Resolver, every StorageServer (`storageserver.actor.cpp:1200`) | hot-path enforcement — checks consult this, never a live DB read | metadata-mutation broadcast, in version order |
| **On-disk per-SS copy** | the SS local storage engine under `persistAuthzPolicyKeys` (`PERSIST_PREFIX "AuthzPolicy/"`) | survive SS reboot | appended to the SS mutation log on apply |
| **Recovery copy** | the `txnStateStore` on proxies/Resolver | rebuild the in-memory map after recovery | written on the live commit path |

**How it is updated.** A set/clear to `\xff/authz/policy/*` is recognized at the CommitProxy as
a *metadata mutation* (`checkSetAuthzPolicyPrefix` / `checkClearAuthzPolicyPrefix` in
`ApplyMetadataMutation.cpp`). On the live path the proxy (a) updates its in-memory map, (b)
writes/clears the `txnStateStore`, and (c) **privatizes** the mutation (shifts the key under
the private system prefix) and broadcasts it. Each StorageServer applies the privatized
mutation in `applyPrivateData` **in version order**, updating its in-memory map *and* appending
the row to its mutation log under `persistAuthzPolicyKeys` (making it durable). All four
representations therefore advance together at the mutation's commit version. A `set` replaces an
identity's entry; a `clear` over the range erases the matching identities. Recovery replay
(`initialCommit`) updates the maps and `txnStateStore` but does **not** re-broadcast.

**Is it sharded? No — it is fully replicated to every storage server.** Ordinary data is
sharded across StorageServers by key range, so a given SS holds only the shards assigned to it.
The policy map is deliberately different: when the CommitProxy privatizes a policy mutation it
reads the **entire** server-tag set and tags the mutation to **all** storage servers —

```cpp
auto allServers = txnStateStore->readRange(serverTagKeys).get();   // every SS
std::set<Tag> allTags; for (auto& kv : allServers) allTags.insert(decodeServerTagValue(kv.value));
...
toCommit->addTags(allTags);                                        // broadcast to all
writeMutation(privatized);
```

so **every** StorageServer ends up with the **complete** policy map regardless of which key
shards it serves (the same all-SS broadcast the deleted tenant map used). This is required for
correctness: a read can land on any shard on any SS, and that SS must be able to authorize it
**locally**, with no cross-server lookup on the hot path. Full replication is also exactly why
the identity count is capped (below) — the cap bounds the per-server size of the replicated map
and the broadcast/replication fan-out.

### Policy distribution (the broadcast)

Distribution is the update mechanism above, viewed as a pipeline: recognize at CommitProxy →
privatize and tag to all SS → ride the existing TLog stream → apply in version order at every
SS. Because policy rides the **same version stream as the data**, every server converges on the
same policy at the same commit versions, and a read can be authorized against the exact policy
as of its read version. A polling cache cannot give this (see *Alternatives Considered*).

### Read enforcement — StorageServer; placement is the point

Reads are checked in the StorageServer handlers via a single `ssAuthzCheck` helper, called in
`getValueQ`, `getKeyValuesQ`, and `getKeyQ`. The **placement** is what makes the plain map
correct:

- **After `waitForVersion(req.version)`** — the map already reflects every policy mutation at or
  before the read version (no stale-allow window).
- **After `findKey` resolves KeySelectors** — the check covers the keys *actually read*, not the
  selector anchor (no selector-offset bypass).

A denied read throws `permission_denied`, which is in the SS's `canReplyWith` set so it flows
through the normal error path and leaks no key/range information. This is intentionally
**fail-closed** (satisfying R5): a revoke that commits within the MVCC window denies the
revoked identity's own in-flight reads — the desired behavior for a security primitive, and the
reason a plain map suffices (see *Alternatives Considered* on `VersionedMap`).

> **Coverage (honest scope).** The POC enforces the three point/range/selector read endpoints
> above. Streaming, mapped, and watch reads (`getKeyValuesStreamQ`, `getMappedKeyValuesQ`,
> `watchValueQ`) are the immediate next increment (see *Rollout*); as a conservative first cut,
> mapped reads for non-admin identities are denied rather than partially checked.

### Write enforcement — CommitProxy; before resolution

Each mutation in a transaction is checked for `W` permission in the **pre-resolution** stage of
the commit pipeline (`CommitProxyServer.cpp`). A denied transaction is rejected whole with
`permission_denied`, its mutations/conflict ranges neutered, and it is marked so later stages
treat it as a no-op (the client reply was already sent). Pre-resolution placement is
load-bearing: a denied transaction must never reach the resolvers, or appliers would disagree
about committed state (next section).

### Bounded state and cross-applier determinism

**Identity cap (R6).** A commit that would create a *new* identity beyond `AUTHZ_MAX_IDENTITIES`
(default 32) is rejected with `authz_too_many_identities`. Updates to an existing identity and
clears always pass.

**Why determinism is the hard part.** The `txnStateStore` (the in-memory system-metadata store
on every CommitProxy and the Resolver, rebuilt from the log at recovery) has one invariant:
**every metadata applier reaches the same state.** So the cap/ACL decision cannot be made only
at the proxy owning the batch — it is extracted into a shared rule
(`authzTxnExceedsIdentityCap`) evaluated **identically** at the owning proxy, the other
proxies, and the Resolver. If they disagreed, their `txnStateStore`s would diverge and recovery
would crash. This was not theoretical: simulation seed `2032453810` exhibited exactly this
divergence from an owner-proxy-only rejection, which drove moving the write-ACL check
pre-resolution and sharing the cap rule across appliers.

**Subspace guard (in progress).** Writes to `\xff/authz/*` must require the admin identity and
never be authorizable by an ordinary grant (else a broad `W` grant could rewrite its own
policy). This guard belongs at the same pre-metadata hook the cap check uses; wiring it there is
remaining work (see *Rollout*).

### Reboot durability — how the policy is reboot-proof

Each holder of the policy map recovers it without any fail-open or spurious-deny window:

- **CommitProxies and the Resolver** rebuild their in-memory map from the `txnStateStore` during
  recovery (`initialCommit` replay) — the rows were written there on the live path, so a
  freshly recovered proxy is correct before it serves.
- **StorageServers** use three legs (mirroring the deleted tenant map, which is the template):
  1. **Persist on apply** — every applied policy mutation is also written to the SS mutation log
     under `persistAuthzPolicyKeys`, durable at the version it applied.
  2. **Restore before serving** — `restoreDurableState()` reads `persistAuthzPolicyKeys` and
     rebuilds the map **before** the SS serves any read.
  3. **One-shot read on fresh recruitment** — a brand-new SS's broadcast tag only receives
     mutations from its registration version onward, so it would never see historical policy.
     At registration it does a one-shot read of `\xff/authz/policy/*` (`initAuthzPolicyMap`) and
     **writes the rows to storage immediately**.

Leg 3 closes a latent hole the tenant-map template shipped with — it populated the map
in-memory only, so a freshly-recruited-then-rebooted server came back empty. Simulation caught
this (see *Testing*). Combined with the check-after-`waitForVersion` placement, this satisfies
R7: an SS that reboots before policy versions are durable restores a correctly-empty map and
replays from `durableVersion+1`, and `waitForVersion` holds reads until that replay reaches the
read version.

### Cluster-internal identity

Cluster-internal traffic (recovery, data distribution, ratekeeper, backup, DR, loopback
self-reads) bypasses authorization by presenting a **single admin CN**
(`AUTHZ_INITIAL_ADMIN_CN`); the check is a plain CN-equality test on the identity already
extracted — no extra cert-field plumbing. The accepted limitation is that one shared admin cert
means any server can act as any identity (cluster-internal cross-role isolation is a
non-requirement). Per-role admin identities — modeled as *distributed policy data* at
`\xff/authz/admin/<cn>`, auditable and individually revocable, rather than a knob — are deferred
(see *Rollout*). The decision order is: knob off → allow; identity == adminCN → allow; empty →
deny; else policy lookup.

### Configuration knobs

| Knob | Type | Default | Purpose |
|---|---|---|---|
| `AUTHZ_ENFORCEMENT_ENABLED` | bool | `false` | Master switch. Off → every check returns *allow*; the feature is inert. |
| `AUTHZ_INITIAL_ADMIN_CN` | string | `""` | Cluster-internal/admin identity (cert CN). Equal identity bypasses checks; empty disables the bypass. |
| `AUTHZ_MAX_IDENTITIES` | int | `32` | Cap on distinct policy identities. Sim-randomized 4–32 under `buggify`. |

### Errors

| Error | Code | Behavior |
|---|---|---|
| `permission_denied` | 6000 (existing) | Denied read/write. An expected, final rejection (in `canReplyWith`, no `SevError`), mirroring the removed `illegal_tenant_access`. |
| `authz_too_many_identities` | 6006 (**new**) | A commit would exceed `AUTHZ_MAX_IDENTITIES`. Final (no retry). |

### Operator workflow (POC)

An operator (presenting the admin identity) **grants** by writing a `PolicyEntry` to
`\xff/authz/policy/<identity>` and **revokes** by clearing that key. A first-class surface — a
`\xff\xff/management/authz/` special-keys subspace plus `fdbcli` commands — is deferred; the
underlying mechanism is identical.

### Where it hooks in

| Concern | File / symbol |
|---|---|
| Policy types & `checkAuthorized` | `fdbclient/include/fdbclient/AuthzPolicy.h` |
| System keys | `fdbclient/SystemData.{h,cpp}` (`\xff/authz/policy/*`) |
| Identity capture | `fdbrpc/FlowTransport.{h,cpp}`, `fdbrpc/include/fdbrpc/TimedRequest.h`, `flow/include/flow/IConnection.h` |
| Distribution + shared cap rule | `fdbserver/logsystem/ApplyMetadataMutation.cpp` (`checkSet/ClearAuthzPolicyPrefix`, `authzTxnExceedsIdentityCap`) |
| Write check + cap | `fdbserver/commitproxy/CommitProxyServer.cpp`, `ProxyCommitData.h` |
| Resolver applier | `fdbserver/resolver/Resolver.cpp` |
| Read checks, persist, restore, init | `fdbserver/storageserver/storageserver.actor.cpp` (`ssAuthzCheck`, `persistAuthzPolicyKeys`, `restoreDurableState`, `initAuthzPolicyMap`) |
| Knobs | `fdbserver/core/ServerKnobs.cpp`, `.../Knobs.h` |
| Error code | `flow/include/flow/error_definitions.h` |
| Workload & test | `fdbserver/workloads/AuthzKeyRangeWorkload.cpp`, `tests/fast/AuthzKeyRange.toml` |

---

## Alternatives Considered

- **Bundling isolation into the key layout (the tenants / metacluster approach).** It pushes
  data into tenant key-prefixes and requires re-import to adopt. This proposal instead leaves
  the keyspace untouched and grants access beside the data.
- **A polling policy cache + version key.** An earlier design had each server poll a dedicated
  `\xff/authz/version` key and re-read the policy on change. It has a staleness window, a
  circular dependency (authorizing the very read that fetches the policy), and no cold-start
  story. The metadata-mutation broadcast is version-consistent, supports atomic revocation, and
  reuses machinery FDB already depends on.
- **Reusing the `isTrustedPeer` bit for cluster self-auth.** `isTrustedPeer` is load-bearing for
  private-endpoint dispatch in `FlowTransport`; overloading it as a "skip authz" signal broke
  every private RPC in simulation. Cluster self-auth is instead a distinct admin identity,
  keeping `isTrustedPeer` single-purpose.
- **A `VersionedMap` for the SS policy map.** Checking *after* `waitForVersion` makes a plain map
  exact as-of the read version, so the extra structure buys nothing — and worse, a versioned map
  would let a revoked identity's in-flight reads continue for the MVCC window, the wrong default
  for a security primitive.
- **`AUTHZ_PRIVILEGED_PEERS` / the `--tls-verify-peers` grammar** for the admin bypass. It
  conflates handshake-trust (who may connect) with data-authz (what an identity may touch), is a
  coarse all-or-nothing match on cert fields (one CA mis-issue ⇒ god mode), and lives outside the
  policy model. Per-role admin, when needed, belongs *in* the policy (`\xff/authz/admin/<cn>`).
- **A real OpenSSL handshake in simulation.** Reproducing OpenSSL inside sim reproduces a
  dependency the code does not own (an anti-pattern). The code only touches the *verified
  identity* and the *handshake outcome*; simulation models exactly those (issued, write-once
  identities), and a real-OpenSSL **contract test** (see *Testing*) keeps that model honest.

---

## Testing Considerations

The feature was developed test-first against FoundationDB's deterministic simulation, then
exercised at scale on Joshua. Each requirement maps to a check below.

### Deterministic simulation workload

`tests/fast/AuthzKeyRange.toml` drives a randomized multi-client workload
(`AuthzKeyRangeWorkload.cpp`) with TLS pinned on (`forceSSL=true`) for determinism and
enforcement enabled. Each tester process is issued **one fixed, write-once identity for its
lifetime** (forgery and mid-life switches are impossible by construction — **R1**), and runs
**concurrently with fault injection** (`Attrition` machine kills/reboots, random data movement)
so reboot durability is exercised against live enforcement (**R7**). The workload asserts that
granted clients are allowed on their own keyspace and denied elsewhere (**R1, R2**), that
un-granted clients are denied everywhere (**R2**), that the admin bypass always succeeds, and
that creating the (cap+1)'th identity is rejected with `authz_too_many_identities` (**R6**).

In pseudocode (one instance runs per simulated client process):

```text
workload AuthzKeyRange:

  constructor(clientId, clientCount):     # identity is fixed once, for the process's life
    isAdmin      = (clientId == 0)
    myCN         = isAdmin ? AUTHZ_INITIAL_ADMIN_CN : "client-<clientId>"
    grantedCount = min(clientCount - 1, AUTHZ_MAX_IDENTITIES)
    granted      = not isAdmin and clientId <= grantedCount
    issueIdentity(myCN)         # write-once: forging or switching identity is impossible
    # client c owns the keyspace ["k<c>/", "k<c>0")

  setup():                      # only the admin runs setup; ALL setups finish before ANY start()
    if not isAdmin: return
    for i in 1..grantedCount:                                  # 1. grant each client its keyspace
        set \xff/authz/policy/client-<i> = { grant(["k<i>/","k<i>0"), W) }   # W implies R
    for j in 1..(AUTHZ_MAX_IDENTITIES - grantedCount):
        set \xff/authz/policy/cap-filler-<j> = { }             # 2. fill identities up to the cap
    try:
        set \xff/authz/policy/cap-overflow = { }               # 3. the (cap+1)'th must be rejected
        fail("cap not enforced")
    except authz_too_many_identities:
        capRejectionOk = true                                  # decision is final — do not retry

  start():                      # every client; ops spread over sim time to overlap reboots
    for op in 0 .. opsPerClient-1:
        delay(0.5 + random)                                    # overlap injected kills/reboots
        if isAdmin:
            target, expectAllow = (a random client's keyspace), true        # admin bypass
        else:
            crossKeyspace = (op == 0) ? true     # force one cross-keyspace probe (expect deny)
                          : (op == 1) ? false     # force one own-keyspace op     (expect allow)
                          :             random < crossProbability
            target      = crossKeyspace ? someOtherClient : self
            expectAllow = (not crossKeyspace) and granted      # un-granted => denied everywhere
        doRandomOp(target, expectAllow)

  doRandomOp(target, expectAllow):
    k  = a random key in target's keyspace
    op = one of { get, getRange, set, clear }
    retry loop:
        try:
            run op in a transaction (commit if it is a write)
            if not expectAllow: fail("expected DENY but was allowed")        # SevError
            else:               record ok (adminOpsOk / ownOpsOk)
            return
        except permission_denied:
            if expectAllow:     fail("expected ALLOW but was denied")        # SevError
            else:               crossDeniedOk += 1                           # correct deny
            return                              # an authorization decision is final — no retry
        except retryable (not_committed, transaction_too_old, ...):
            continue

  check():     # per-client verdict; any fail(...) above already raised SevError
    pass iff   isAdmin   -> adminOpsOk    > 0 and capRejectionOk
             ; granted   -> ownOpsOk      > 0 and crossDeniedOk > 0
             ; otherwise -> crossDeniedOk > 0
```

### Simulation-driven hardening (bugs found)

Simulation found **two real bugs** during hardening, both fixed:

1. A **fresh-recruit durability hole** — a newly recruited StorageServer that rebooted came back
   with an empty policy map and wrongly denied. (The upstream tenant-map code this was modeled
   on shipped with the same hole.) Fixed by leg 3 of reboot durability.
2. A **spurious-deny window during post-reboot tlog replay** — the earlier read-check placement
   consulted the map *before* `waitForVersion`, denying granted clients while replay was still
   in flight. Fixed by the check-after-`waitForVersion` placement.

A third issue — `txnStateStore` divergence from an owner-proxy-only rejection (seed
`2032453810`) — drove the determinism design.

### Joshua at scale

| Metric | Value |
|---|---|
| Ensemble | `20260612-071559-joshua-fb29b69dca204978` |
| Runs | **30,000 / 30,000 passed** |
| Failures | **0** |
| `fail_fast` | enabled — any single failure halts the entire ensemble |
| Per-run timeout | 5,400 s |
| Wall-clock | 13:19:20 |
| Completed | 2026-06-12 |

Because `fail_fast` was on, running all 30,000 to completion means **no seed failed**. This is
in addition to 100/100 passing local seeds during development.

### Planned additional testing

- A **real-OpenSSL contract test** (`fdbrpc/tests/AuthzTlsTest.cpp`) asserting the identity the
  simulation models matches a real TLS handshake — including a forged-cert case (client cert
  from an untrusted CA → handshake fails / empty identity). This keeps the simulation's identity
  fake honest against production TLS.
- Workload coverage for the streaming/mapped/watch read endpoints as that enforcement lands.

---

## Observability / Supportability Considerations

Enforcement and distribution emit `SevInfo` trace events, so denials, admin-bypass, and policy
propagation are visible in the trace logs:

- `AuthzCommitCheck` (CommitProxy) — write-side allow/deny decisions.
- `AuthzPolicyBroadcast` / `AuthzPolicyBroadcastClear` (CommitProxy) — a policy set/clear being
  privatized and broadcast, with the identity, grant count, tag fan-out, and version.
- StorageServer read denials are traced per occurrence.

These let an operator confirm a grant has propagated (broadcast event + version) and diagnose an
unexpected denial (which endpoint, which identity, which range). The recovery-critical paths
(`ApplyMetadataMutation`, `applyPrivateData`) are existing, already-instrumented code. New
metrics worth adding before GA: a per-server policy-map size gauge (to watch against the cap)
and a denial-rate counter. No new SLOs or alerts are proposed for the POC; an enforcing
deployment would likely alert on an abnormal denial rate.

---

## Rollout / Migration Considerations

### Compatibility

- **Fully opt-in.** With `AUTHZ_ENFORCEMENT_ENABLED=false` (default) every check returns
  *allow*; no behavioral change and no measurable data-path cost (**R4**). Enabling enforcement
  is an operator decision.
- **Additive schema.** One new system key range (`\xff/authz/policy/*`), invisible to client
  code that does not read system keys. No data migration (**R3**).
- **No protocol version gate.** The feature is additive; no cluster-version handshake is needed
  to deploy it.
- **Additive errors.** `authz_too_many_identities` (6006) is new; `permission_denied` (6000)
  already exists and is now treated as expected/final.
- **Rollback.** Flipping the knob off restores prior behavior immediately; policy rows remain
  harmless system data and can be cleared.

### Delivery plan

Proposed for upstream as **three independently reviewable MRs**, in dependency order:

1. **Simulation TLS + identity** — improve how TLS is modeled in simulation and give each
   simulated process a verified, write-once peer identity (its Subject CN). Confined to the
   simulator and test code; no production data-path behavior change, so it is inert and can land
   first.
2. **Key-range authorization** — the core feature: wiring the verified peer identity through the
   production transport, then policy distribution, read/write enforcement, the identity cap, and
   reboot durability — gated by `AUTHZ_ENFORCEMENT_ENABLED` (default off). Validated in
   simulation (building on MR1) and by a real-OpenSSL contract test; this is what the reference
   branch prototypes and the Joshua ensemble exercises.
3. **Operator UX (`fdbcli`)** — the `\xff\xff/management/authz/` special-keys subspace and
   `fdbcli` grant/revoke/list commands over the MR2 mechanism.

Still to finish within MR2: read coverage for the streaming/mapped/watch endpoints and the
`\xff/authz/*` subspace guard. Later follow-ups: per-role admin identities
(`\xff/authz/admin/<cn>`) and a per-transaction signed sub-identity for in-layer customer
isolation.

**Reviewer ask:** feedback on the model (CN-as-identity, default-deny grants, single admin
identity), the enforcement placement and cross-applier determinism, the replicated (not sharded)
storage, and the three-MR split — before the MRs are opened.

---

## References

- Reference POC: branch `poc/key-range-authz-v2`, based on apple `upstream/main` (`72fca11de1`).
- Internal design docs (in `design/`): `key-range-authz.md` (v0 — threat model, identity,
  rationale, alternatives), `key-range-authz-v1.md` (v1 — broadcast distribution, admin-CN
  decoupling), `key-range-authz-v2.md` (v2 — placement, durability, cap, simulation fidelity).
- Tenant / metacluster removal (the broadcast + persistence templates): PR #12583, commit
  `bab7637d8`.
- On simulation fakes that prove correctness:
  <https://pierrezemb.fr/posts/designing-fakes-that-prove-correctness/>.
- Template: `design/design-doc-template.md`.
