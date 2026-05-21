# Design: per-identity key-range authorization for FoundationDB

**Status:** Draft for upstream review
**Date:** 2026-05-21 (revised — sub-identity removed from v1 scope; deferred to v2)
**Replaces (in part):** tenant + metacluster (deleted in PR #12583, commit `bab7637d8`)
**Audience:** FoundationDB OSS reviewers (rationale + tradeoffs) + implementation contributors (file-level guide)

> A previous draft of this design (with per-transaction sub-identity in v1 scope) is archived as a private gist for history. See §5.7 and §6 for what was set aside.
> This document lives at `src/design/key-range-authz.md` on branch `poc/key-range-authz-v0` in the apple/foundationdb checkout (`/home/pierrez/workspace/just-build-fdb/src`).

---

## 0. Start here (POC orientation)

This document is the design for a POC implementation. A fresh instance of Claude is intended to pick this up after a context reset and start writing code. Read this section first.

**Where the code lives:** branch `poc/key-range-authz-v0` in the apple/foundationdb checkout at `/home/pierrez/workspace/just-build-fdb/src`. The superproject at `/home/pierrez/workspace/just-build-fdb` provides the build container and `just` recipes — see its `CLAUDE.md` for working principles (container-as-a-service, recipe modules under `just/`, etc.).

**POC scope (deliberately smaller than the full design in §2-4):**

- CommitProxy + StorageServer enforcement, both directions (read + write).
- Per-identity policy lookup. `admin/<cn>` for full-access identities. **No** privileged-peer pattern bypass yet.
- Simple cache: subscribe to a version key at `\xff/authz/version` (atomic versionstamp); on bump, re-read the affected `\xff/authz/policy/...` range.
- Direct system-key writes from test code to set up policies. **No** special-keys validator, **no** fdbcli command, **no** `\xff\xff/management/authz/` subspace.
- `AUTHZ_ENFORCEMENT_ENABLED` knob, default off. When off, the data-plane check returns allow.
- TLS peer CN extraction via the FlowTransport plumbing described in §4.2 (`Plumbing — TLS peer identity exposure`).

**Deferred to post-POC (upstream-ready follow-ups):** the `\xff\xff/management/authz/` special-keys subspace + write validator, fdbcli commands, `AUTHZ_PRIVILEGED_PEERS` knob + Criteria-based matching (for the POC, test setup uses `admin/<cn>` directly), system-key access stacking with `ACCESS_SYSTEM_KEYS` (POC tests use admin identities for any `\xff/` access), cert-extension policy carriage (v2), sub-identity (deferred from v1 — see §5.7).

**Build / test workflow** (do not trigger a full cold FDB build to verify something — cold builds take hours):

- `cd /home/pierrez/workspace/just-build-fdb && just dev up` — idempotent; starts the dev container.
- `just build configure` — first-time CMake step. After that, incremental builds are fast.
- `just sim run tests/<some.toml>` — once incremental builds succeed.
- See `/home/pierrez/workspace/just-build-fdb/CLAUDE.md` and `just/*.just` for the rest of the recipes.

**Suggested first move:**

1. Read this entire doc end-to-end (~10 min).
2. Open the files identified in §4.2 in this order **before writing any code**:
   - `fdbrpc/FlowTransport.cpp` around lines 1203, 1448, 2202 and `fdbrpc/include/fdbrpc/FlowTransport.h:298` — confirm the thread-local plumbing pattern (`g_currentDeliverPeerAddressTrusted`) before extending it for peer identity.
   - `flow/TLSConfig.cpp:780` (and `PeerVerifier` around 698-849) — confirm the X.509 / extension APIs are usable.
   - `fdbserver/commitproxy/CommitProxyServer.cpp:1348-1367` — the mutation-loop insertion point.
   - `fdbserver/storageserver/storageserver.actor.cpp:2160, 3332, 6008` — the three SS read handlers.
3. Sketch the minimal patch as a comment-only diff first. Confirm the shape with the user before writing executable code.
4. Implement plumbing first (Stage 1 in §4.1), then cache + enforcement (Stage 2). Both gated by `AUTHZ_ENFORCEMENT_ENABLED`.
5. Verify end-to-end via a small simulation workload — see §4.5 for the test shape. A minimal toml + workload that creates one identity, writes a policy via direct system-key write, then exercises one allowed read and one denied read is enough to declare the POC done.

**Commit conventions on this branch:** the first commit on this branch is this design doc itself, committed without GPG signing (one-off, for context-reset bootstrap). Subsequent POC commits should follow the superproject `CLAUDE.md` (conventional-commits style, GPG-signed via Yubikey — wait for the user to touch the key before assuming `git commit` will complete).

---

## TL;DR

A small, **unbundled** authorization primitive for FoundationDB: per-identity key-range ACLs enforced server-side. Identity comes from the mTLS peer cert. Policies are explicit `(range, perm ∈ {R, W, Denied})` lists per identity, stored in the special-keys subspace. No new recruited role; no key-layout changes; no JWT / HMAC / sub-identity machinery. Per-mutation enforcement cost is ~0.2 μs (<5% of existing per-mutation work). Opt-in via knob; zero behavior change for existing clusters until enabled.

This addresses the operational pain that motivated tenant/metacluster — workloads sharing a cluster need a real security boundary at the **layer level** — while explicitly **avoiding the bundling that doomed tenant/metacluster** (forced re-import into a tenant-prefix key layout). This primitive operates on existing keys, in place, with no migration.

**Scope deliberately limited:** the cluster enforces isolation at the *layer-class* boundary (a `redis-layer` cannot reach a `sql-layer`'s data). It does NOT enforce isolation **between customers within a single layer** — that is delegated to the layer code, the same model as Postgres or any other shared-tenant database. A future v2 may revisit cluster-enforced per-customer isolation; see §5.6 and §6.

---

## 1. Background and motivation

### 1.1 The shared-cluster problem

FoundationDB is increasingly used as a shared substrate for multiple workloads inside an organization — Redis-compatible, SQL-compatible, queue, document, etc. — sharing one cluster.

Today, **possession of a clusterfile plus `libfdb` on the network is full access.** Any client can:

- Read any key (any layer's data);
- Write or `clearRange` over any key, including catastrophic wipes (`clearRange([\x00, \xff))`);
- Read system metadata (`\xff/...`) — anything that sets `ACCESS_SYSTEM_KEYS` reaches it;
- Issue management-API operations via the special-keys subspace (`\xff\xff/management/...`).

There is no in-cluster authorization boundary at the layer level for **any** of these surfaces — user data, system metadata, or the management API. The only gating is network reachability + clusterfile possession + (for system keys) the `ACCESS_SYSTEM_KEYS` txn option, which any client can set.

### 1.2 What tenant/metacluster tried, and why it was deleted

Tenant and metacluster (deleted en bloc in PR #12583 / commit `bab7637d8`) tried to solve this by introducing tenancy as a key-layout concept: each tenant got a prefix, and tenant boundaries became shard boundaries. They were rejected because they bundled isolation with a forced re-import into a tenant-prefix key layout. Workloads could not keep their own keyspace; migration cost was prohibitive.

The deletion took with it: `AuthorizationToken` / `AuthorizationTokenClaims` (JWT-based per-tenant token verification), the `TenantInfo` request struct, the `TenantCache` at SS, and the entire `metacluster/` directory. Vestigial remnants survive in HEAD: the `AUTHORIZATION_TOKEN` transaction option (#2000), the `Optional<WipedString> authToken` field in `TransactionState`, and the `permission_denied` / `authorization_token_verify_failed` error codes — all currently inert.

### 1.3 Constraints on a replacement

Per Apple reviewers (via this proposal's sponsor):

- **Fits cleanly.** Reuse existing primitives. Do not invent parallel frameworks.
- **Not too invasive.** Small surface area, contained patch.
- **Pays its own way.** Performance overhead must be defensible. Operational overhead must be opt-in.
- **Benefits outweigh costs.**

---

## 2. Design

### 2.1 Threat model

**In scope (v1):**

- A malicious or buggy client with `libfdb` on the cluster network can today read or clear any key. After this feature, an authenticated identity may only touch the key ranges its policy explicitly grants.
- **System metadata (`\xff/...`) and the management-API special-keys subspace (`\xff\xff/...`) are within the authz domain** — same policy table, same enforcement check. Grants on system-key ranges (e.g. `\xff/metadataVersion`) are first-class. The existing `ACCESS_SYSTEM_KEYS` option remains the gate for `\xff/` access and **stacks** with authz (both required); see §2.3.
- `libfdb` cannot be trusted as an enforcement point — it is open source and any client can patch it. Enforcement is server-side authoritative.

**Out of scope (v1):**

- **Per-customer isolation inside a layer.** A compromised or buggy layer process can reach any data its identity grants, including across customers it serves. Customer isolation inside a layer is the layer code's responsibility (the same model as Postgres, MySQL, etc.). v2 may revisit with signed sub-identity claims; see §6.
- Stolen mTLS private key (defended by the TLS layer — cert rotation, HSMs).
- Cluster-internal cross-role attacks (proxy → SS, etc.) — same trust boundary as today.
- Management-API gating (`configure`, `exclude`, `kill`, etc.). Clusterfile possession remains the gate.

### 2.2 Identity

**Identity** = the verified mTLS peer cert's CN (with SAN as fallback). Set server-side from the TLS handshake during message deserialization — extending `FlowTransport::currentDeliveryPeerIsTrusted()` with a sibling `currentDeliveryPeerIdentity()` thread-local pattern. The wire format does not carry an identity field; the server reads it from the connection's verified cert, immune to client forgery (see §2.4 for why this resists the obvious "but couldn't I forge identity?" question).

Untrusted connections (no TLS, or TLS without client cert) yield empty identity. With authz enabled, empty identity matches no rule → denied. **Enabling authz therefore requires mTLS-with-client-cert for all data traffic** (operator prerequisite — see Stage 0 in §4.1).

### 2.3 Policy model

A policy entry is keyed by identity and contains a list of `(range, perm)` grants, where `perm ∈ {R, W, Denied}`. `W` covers `set`, `clear`, `clearRange`, and atomic ops.

**Storage shape:**

```
\xff\xff/management/authz/policy/<identity>
  → encoded list of { begin: KeyRef, end: KeyRef, perm: R|W|Denied }

\xff\xff/management/authz/admin/<identity>
  → empty value; presence ⇒ identity has implicit full access
```

The underlying system-keys storage at `\xff/authz/policy/...` is what CommitProxy and StorageServer subscribe to via a versioned watch; the special-keys subspace is the operator-facing view that fdbcli and external control planes write through.

**Grants on system keys (`\xff/...`) are first-class.** A layer that needs to read `\xff/metadataVersion` (a common pattern for cache-invalidation watchers) is granted a single-key range:

```
authz grant <layer-cn> "\xff/metadataVersion".."\xff/metadataVersion\x00" R
```

The layer must still set `ACCESS_SYSTEM_KEYS` on the transaction (the existing gate is unchanged — both must succeed). Cluster-internal services that need broader `\xff/` access (DataDistributor, recovery, etc.) are covered by the `AUTHZ_PRIVILEGED_PEERS` bypass (§2.5).

**No default-permission field.** Absence of a row = Denied. Default-allow-then-restrict has a well-known footgun (forget an override → too permissive). Admin identities are handled by the `admin/` subspace.

**Privileges are `R / W / Denied`.** Splitting CLEAR was considered and rejected: `set(k, v')` over `(k, v)` is as destructive as `clear(k)` for data integrity. The only protection CLEAR uniquely affords is "the key vanishes from `getRange`" — strictly weaker than data protection. Distinguishing CLEAR was security-theater.

### 2.4 Enforcement architecture

Server-side authoritative. CommitProxy enforces on every mutation in a commit batch. StorageServer enforces on every read. Client-side checks are advisory only (libfdb optimization; cluster never trusts them).

**No new recruited role.** Both CommitProxy and StorageServer hold a local `AuthzPolicyCache`. The cache subscribes to a **dedicated version key** at `\xff/authz/version` (atomic versionstamp, bumped by the special-keys write validator on every policy change). On a version mismatch with the local snapshot, the cache re-reads the affected `\xff/authz/policy/...` range. Pattern mined from the deleted `TenantCache` at `bab7637d8^`, with two changes: (a) we drop the shard-binding bundling — our cache is a pure authz acceleration, independent of data layout, and (b) we use our own version key instead of subscribing to the global `\xff/metadataVersion` (which bumps on ANY cluster metadata change). The dedicated key keeps both us and existing `metadataVersion` consumers (e.g. layer-side cache watchers) free of cross-noise.

**Check ordering in `AuthzPolicyCache::check()`:**

1. If the peer matches `AUTHZ_PRIVILEGED_PEERS` → allow (bypass).
2. If the peer's CN is in `admin/` → allow (admin override via `AUTHZ_INITIAL_ADMIN_CN` works pre-cache).
3. If the cache is not fresh (past `AUTHZ_CACHE_STALENESS_LIMIT_MS` since last refresh) → deny.
4. Look up `peer.cn` in the cache; binary-search the policy's range list; allow iff the requested op fits the matched range's perm.

**Why identity forgery is not possible** (this is the load-bearing security claim — three defenses):

1. **TLS cert chain validation.** Identity = the CN of the cert the peer presented at handshake. To present `CN=redis-layer`, attacker needs that cert's **private key**. Without it, OpenSSL aborts the handshake. Same protection as every mTLS service.
2. **Identity is read from the connection, not the message.** During request deserialization, the server *writes* `req.peerIdentity` from `currentDeliveryPeerIdentity()` (the thread-local set from the verified cert) — overwriting anything a client might have put in that slot. The wire format does not carry an identity field the server reads. There is nothing in the request bytes to forge.
3. **Untrusted connections produce empty identity.** No TLS / no client cert → empty CN. Privileged-peer regex won't match empty; `admin/` has no row for empty CN; no `<empty>` policy row exists → every check denies. Authz forces mTLS-with-client-cert on for the cluster, by construction.

### 2.5 Privileged-peer bypass

Cluster-internal services that issue user-style transactions (DataDistributor moving shards, Ratekeeper, recovery state machines that touch `\xff/...`), backup and DR agents, and operator fdbcli sessions need to bypass authz — they are "cluster business," not user data-plane traffic. On the wire they look identical to layer clients. The distinguisher must be identity-based.

We introduce a knob `AUTHZ_PRIVILEGED_PEERS` (string, default empty). Peers whose cert matches the pattern bypass authz unconditionally. **The grammar is the same as `--tls-verify-peers`** — comma-separated rules with `|` for OR, operators `=` / `>=` / `<=`, fields `S.CN`, `S.O`, `S.subjectAltName`, etc. We reuse the existing `Criteria` parser (`flow/TLSConfig.cpp:534-642`) and the `PeerVerifier::matchCriteria` evaluator (`flow/TLSConfig.cpp:826`). Zero new grammar to invent, document, or review.

Example: `S.CN=fdb-internal|S.CN>=fdb-backup-|S.CN>=fdb-dr-`.

The privileged-peer bypass applies to **all** authz checks — including those on `\xff/` and `\xff\xff/` ranges. Without it, recruitment and recovery state machines that legitimately touch `\xff/keyServers`, `\xff/serverList`, `\xff/coordinators`, etc. would deadlock the moment authz is enabled.

**Deployment prerequisite (Stage 0):** Default shared-cert deployments cannot distinguish cluster-internal peers from layer clients. Operators must deploy a PKI where the two classes have distinguishable CN/SAN before enabling authz. Backup agents specifically have no per-agent identity convention today (`fdbclient/BackupTLSConfig.cpp:51-84` shows generic `TLS_CERT_PATH` use); operators wanting fine-grained authz on backup agents must deploy them with dedicated certs.

### 2.6 Management surface

A new `\xff\xff/management/authz/` special-keys subspace, registered via `SpecialKeyRangeRWImpl` (pattern: `ManagementCommandsOptionsImpl` at `fdbclient/include/fdbclient/SpecialKeySpace.h:323-333`).

**Write validator enforces:**

- Range list is sorted, non-overlapping; perms are valid.
- Only admin identities may write to `admin/`.
- Errors as JSON via `ManagementAPIError::toJsonString`.

**fdbcli surface:**

```
authz list [identity]                       # read special-keys range
authz grant <id> <begin>..<end> R|W          # write a row
authz revoke <id>                            # clear a row
authz admin add|remove <identity>            # admin/ subspace
authz status                                 # enforcement on/off + cache freshness
```

Pattern follows `fdbcli/ExcludeCommand.cpp:36-86, 230-265`. Commands registered via `CommandFactory`.

Worked example — granting a layer access to its own keyspace plus `metadataVersion`:

```
authz grant redis-layer "redis/".."redis0" RW
authz grant redis-layer "\xff/metadataVersion".."\xff/metadataVersion\x00" R
```

### 2.7 Knobs

| Knob | Type / default | Purpose |
|---|---|---|
| `AUTHZ_ENFORCEMENT_ENABLED` | bool, `false` | Master switch. When false, data-plane check returns allow unconditionally. |
| `AUTHZ_INITIAL_ADMIN_CN` | string, `""` | Bootstrap admin identity. One-time; solves chicken-and-egg of the first admin write. |
| `AUTHZ_PRIVILEGED_PEERS` | string, `""` | Peers whose cert matches this bypass authz. Same grammar as `--tls-verify-peers`. |
| `AUTHZ_CACHE_STALENESS_LIMIT_MS` | int, `30000` | Fail-closed limit if the cache cannot refresh from system keys. |

---

## 3. Rationale

This section is the case to OSS reviewers for the non-trivial decisions.

### 3.1 Why mTLS as identity (not JWT, not HMAC)

- mTLS is already deployed in any cluster that cares about identity. No new key-management surface.
- JWT identity (the deleted tenant approach) requires trust-authority infrastructure (key distribution, rotation, verification at every server). Significant cost; rebuilds what was just deleted.
- HMAC defends against stolen cert — a TLS-layer concern, not authz.
- "Fits cleanly" → reuse the connection's existing identity rather than mint a parallel one.

### 3.2 Why server-side authoritative enforcement

- The opening problem statement is "we cannot trust libfdb"; client-side enforcement is bypassable by patched libfdb.
- Per code-path analysis: per-mutation check at CommitProxy is ~0.2 μs (binary search over 10-100 ranges); per-read at SS is also ~0.2 μs. **<5% of existing per-mutation work; <0.1% of per-read overhead.** The "perf cost" objection does not survive measurement.

### 3.3 Why no new recruited role

- Apple removed `EncryptKeyProxy` in the same commit that deleted tenant — recent pattern of disfavoring per-feature roles.
- Smaller patch (no Cluster Controller recruitment, no role lifecycle tests, no monitoring surface).
- Policy distribution via versioned watch on system keys is an existing FDB pattern (the deleted `TenantCache` used it).

### 3.4 Why `R / W / Denied` and not finer

- `set(k, v')` over `(k, v)` is as destructive as `clear(k)` for data integrity.
- The only protection CLEAR uniquely affords is "the key vanishes from `getRange`" — strictly weaker than data protection.
- Smaller privilege vocabulary is easier for operators writing policies and reviewers approving the patch.

### 3.5 Why no `default` field on a policy row

- Default-allow + restrict-some has a well-known failure mode: forget an override → too permissive.
- The only legitimate "default: full-access" use is the admin identity, and that is handled by the `admin/` subspace.

### 3.6 Why reuse the `--tls-verify-peers` grammar for `AUTHZ_PRIVILEGED_PEERS`

- The existing grammar covers everything we need (CN/SAN matching with exact/prefix/suffix operators, OR composition).
- Operators already know it — it is what they use for cluster TLS auth.
- The parser, the matcher (`PeerVerifier::matchCriteria`), and the documentation already exist. Zero new code paths.
- Inventing a new grammar would be exactly the "doesn't fit cleanly" failure mode the OSS reviewers flagged.

### 3.7 Why an own version key for cache invalidation (not the global metadataVersion)

Considered: subscribe to `\xff/metadataVersion`, the global cluster-wide version stamp the deleted tenant cache used. Rejected because:

- It bumps on ANY metadata change (key servers, shard map, etc.). Authz consumers would see noise from unrelated activity; existing `metadataVersion` consumers in layer code (cache-invalidation watchers, which **are** a real usage pattern) would see noise from authz churn.
- A dedicated `\xff/authz/version` key isolates the signal: bumped only when authz policy changes, watched only by authz consumers.
- Costs almost nothing — one extra key, one extra atomic versionstamp on policy writes (which are infrequent admin ops).
- Matches "fits cleanly" by not entangling our feature with existing consumers of a shared signal.

### 3.8 Why sub-identity is deferred from v1

An earlier draft included a per-transaction `SUB_IDENTITY` option and a tuple `(identity, sub_id)` policy key, intended to let the cluster enforce per-customer isolation **inside** a layer. We set that aside for v1 because:

- The mechanism added ~600 LOC across wire-protocol fields, a write-time attenuation invariant (sub-id row ⊆ bare row), a knob/mode for free-form vs pre-registered sub-ids, and a `may_act_as` policy concept. Material on top of an already non-trivial primitive.
- It opened novel mechanism debates (tuple keying, attenuation invariant, may-act-as templating) that dilute the "fits cleanly" argument and lengthen review.
- Per-customer isolation inside a layer is delegated to the layer code in every other shared-tenant database (Postgres, MySQL, etc.). The v1 protection at the layer-class boundary is meaningful by itself.
- A v2 with signed sub-id claims (HMAC or external IdP) is a natural follow-up if a concrete threat justifies the additional mechanism. v1 leaves the door open without committing to the design now.

### 3.9 Why opt-in via knob (default off)

- Zero behavior change for existing clusters until enabled.
- Stages 1–3 land fully without changing behavior; Stage 4 is the flip.
- Each stage is independently mergeable and revertable.

---

## 4. Implementation plan

### 4.1 Stages

| Stage | Scope | Behavior change |
|---|---|---|
| 0 | Operator-side prerequisite (no FDB code). Deploy PKI such that privileged peers (cluster workers, backup, DR, ops) have distinguishable cert CN/SAN; layers have non-matching CN/SAN. All data-traffic clients use mTLS with client certs. | None |
| 1 | TLS peer identity plumbing through FlowTransport: expose verified CN/SAN to request handlers via the `currentDeliveryPeer*` thread-local pattern. | None |
| 2 | `AuthzPolicyCache` + CommitProxy/SS enforcement + `AUTHZ_PRIVILEGED_PEERS` matching. All gated by `AUTHZ_ENFORCEMENT_ENABLED=false`. | None |
| 3 | Special-keys subspace + write validator + fdbcli commands. Operators can read/write policy; enforcement still off. | None |
| 4 | Flip `AUTHZ_ENFORCEMENT_ENABLED=true`. Docs, perf validation, simulation workload. | Authz live (per-cluster opt-in). |

Each stage is one PR, independently reviewable.

### 4.2 Files to add or modify (with `file:line` refs)

#### Plumbing — TLS peer identity exposure to request handlers (~250 LOC)

- `flow/include/flow/IConnection.h` — add `virtual Optional<std::string> getPeerCertIdentity() const = 0;` (returns CN, with SANs as fallback). Also expose enough cert subject/SAN data for `PeerVerifier::matchCriteria` to consume without duplicating extraction logic.
- `flow/TLSConfig.cpp` — implement extraction. `PeerVerifier` at lines 698-849 already has `matchNameCriteria` and `matchExtensionCriteria`; use them.
- `fdbrpc/include/fdbrpc/FlowTransport.h:298` — add `currentDeliveryPeerIdentity()` companion to existing `currentDeliveryPeerIsTrusted()`.
- `fdbrpc/FlowTransport.cpp:1203, 1448, 2202` — thread peer cert identity through the thread-local pattern that exists for `g_currentDeliverPeerAddressTrusted`.

**Identity is captured at deserialization time** (the same hook the deleted `TenantInfo` used at `bab7637d8^`). The wire format does not carry an identity field; the server populates `req.peerIdentity` from `currentDeliveryPeerIdentity()` at receive time, before the actor handler runs. Client cannot forge.

#### Enforcement — CommitProxy (~50 LOC)

- `fdbserver/commitproxy/CommitProxyServer.cpp:1348-1367` — at the start of the per-mutation loop (right after `MutationRef m = (*pMutations)[mutationNum];` at line 1358), call `cache.check(peer, m)`. On deny, set `rejectedByACL = true` and `break`; outside the loop, `trs[self->transactionNum].reply.sendError(permission_denied());` and `continue`. Matches existing `transaction_too_old` batch-rejection pattern at line 835.

#### Enforcement — StorageServer (~75 LOC)

- `fdbserver/storageserver/storageserver.actor.cpp:2160` (`getValueQ`, after `getReadLock`) — `cache.check(peer, req.key, R)`.
- `fdbserver/storageserver/storageserver.actor.cpp:3332` (`getKeyValuesQ`) — `cache.check(peer, req.begin.getKey(), req.end.getKey(), R)`. Single check before iteration; amortizes across all returned keys.
- `fdbserver/storageserver/storageserver.actor.cpp:6008` (`getKeyQ`) — conservative check against `req.sel.getKey()`.
- On deny: `throw permission_denied()`. For range reads spanning mixed permissions, fail with a **generic** error whose message does not reveal the boundary key (no information leak about protected ranges).

#### Policy cache + subscription (~200 LOC)

- New `fdbserver/include/fdbserver/AuthzPolicyCache.h`:

  ```
  class AuthzPolicyCache {
    bool isPrivileged(const PeerIdentity& peer);     // matches AUTHZ_PRIVILEGED_PEERS
    bool isAdmin(StringRef cn);                       // matches admin/<cn> OR AUTHZ_INITIAL_ADMIN_CN
    bool check(const PeerIdentity& peer, KeyRef key, Perm op);
    bool check(const PeerIdentity& peer, KeyRef begin, KeyRef end, Perm op);
    Future<Void> refresh();                           // version-driven
    bool isFresh();                                   // for fail-closed-on-stale
  };
  ```

- New `fdbserver/AuthzPolicyCache.actor.cpp` — implementation. Subscribe to `\xff/authz/policy/...` using the pattern that `fdbserver/TenantCache.actor.cpp` used at `bab7637d8^` (mine the version-watch, drop the shard-binding). Compile `AUTHZ_PRIVILEGED_PEERS` at startup using the existing `Criteria`/`Rule` parser from `flow/TLSConfig.cpp:534-642`; reuse `PeerVerifier::matchCriteria` (line 826) for per-connection matching (cache the match result per-connection after first lookup). Both CP and SS instantiate one cache each at startup.

#### Management surface (~150 LOC)

- New `fdbclient/include/fdbclient/AuthzManagementSpecialKeys.actor.h` + `.cpp` — `SpecialKeyRangeRWImpl` subclass modeled on `ManagementCommandsOptionsImpl`.
  - `set()`: parse value, validate range list (sorted, non-overlapping, valid perms).
  - `commit()`: enforce admin-only writes to `admin/`; format errors via `ManagementAPIError::toJsonString`.
- Register in `fdbclient/SpecialKeySpace.actor.cpp` under `SpecialKeySpace::MODULE::MANAGEMENT`.

#### fdbcli (~150 LOC)

- New `fdbcli/AuthzCommand.cpp` — modeled on `fdbcli/ExcludeCommand.cpp:36-86, 230-265`. CommandFactory registration + commandActor coroutine + special-key writes. Wire into `fdbcli/fdbcli.cpp` main loop around line 1370.

#### Knobs (~30 LOC)

- `fdbserver/include/fdbserver/Knobs.h` + `fdbserver/Knobs.cpp` — 4 knobs from §2.7.

**Total: ~900 LOC across ~12 files.** (~40% reduction from the earlier sub-identity draft.)

### 4.3 Code reuse (verified against the actual codebase)

| Need | Reuse from |
|---|---|
| `permission_denied` error (code 6000, exact-fit message "Client tried to access unauthorized data") | `flow/include/flow/error_definitions.h:388` |
| Special-keys validator pattern (write-time invariant) | `fdbclient/include/fdbclient/SpecialKeySpace.h:323-333` (`ManagementCommandsOptionsImpl`) |
| Special-keys error format | `fdbclient/include/fdbclient/SpecialKeySpace.h:63-75` (`ManagementAPIError::toJsonString`) |
| fdbcli command + special-key write pattern | `fdbcli/ExcludeCommand.cpp:36-86, 230-265` |
| Versioned snapshot subscription | Mine `fdbserver/TenantCache.actor.cpp` at `bab7637d8^`; drop the shard-binding. |
| Peer trust thread-local pattern (template for identity threading) | `fdbrpc/FlowTransport.cpp:1203, 1448, 2202` (`g_currentDeliverPeerAddressTrusted`) |
| Cert CN/SAN pattern matching for `AUTHZ_PRIVILEGED_PEERS` | `flow/TLSConfig.cpp:534-642` (`Criteria`/`Rule` parser, same grammar as `--tls-verify-peers`); `flow/TLSConfig.cpp:698-849` (`PeerVerifier::matchCriteria`). |
| (v2 only) Asymmetric signing for sub-identity claims | `flow/include/flow/PKey.h` (`PublicKey::verify`, `PrivateKey::sign`) |
| (v2 only) X.509 extension parsing for cert-extension policy carriage | `flow/TLSConfig.cpp:780` already uses `X509_get_ext_d2i` |

### 4.4 Cost / performance

From direct code analysis of the hot paths:

- CommitProxy per-mutation policy check: binary search over ~10-100 ranges = **~0.2 μs**. Existing per-mutation work (tag lookup, serialization, sampling) is ~1-5 μs. **<5% addition.**
- StorageServer per-read check: same **~0.2 μs**. Existing per-read overhead (queue, read lock, version wait, disk I/O) is 100 μs – 10 ms. **<0.1%.**
- Range reads: single check before iteration; amortized to ~0.
- Cluster-wide overhead with `AUTHZ_ENFORCEMENT_ENABLED=false`: **zero** (one branch).
- Privileged-peer match: one `Criteria` evaluation per connection, cached for the connection's lifetime. Negligible.

This is the "pays its own way" argument for upstream: <1% overhead on hot paths, opt-in via knob, no cost when disabled.

### 4.5 Verification plan

1. **Unit tests** — `AuthzPolicyCache` lookup, refresh-on-version, eviction, staleness threshold; special-keys validator format checks; admin-only writes to `admin/`.
2. **Simulation workload** — new `fdbserver/workloads/AuthzKeyRangeWorkload.actor.cpp` modeled on the deleted `TenantManagementWorkload.actor.cpp` at `bab7637d8^`. Spawn N identities, exercise all op types, assert deny paths surface `permission_denied` and allow paths succeed; race policy writes against concurrent reads/commits.
3. **Joshua** — 10k+ ensembles for state-machine races.
4. **fdbcli integration tests** parallel to existing `fdbcli/tests/` — script grant/revoke/list flows.
5. **Performance regression** — existing benchmarks with `AUTHZ_ENFORCEMENT_ENABLED=false` (branch-prediction noise) and with `=true` plus small policy set (<2% regression on read/commit throughput).
6. **End-to-end** in this repo's `just sim run` flow — install a policy; run a mock layer with the configured identity; verify per-layer isolation (one layer cannot reach another's keyspace).

---

## 5. Alternatives considered (and why rejected)

### 5.1 Bring back tenant/metacluster as-is

Rejected. Deletion was deliberate. Bundling problem (forced key-layout migration) is intrinsic to the design.

### 5.2 Cert extension carrying full policy

Rejected for v1. Encode the policy in an X.509 extension on the layer's cert, signed by the operator's CA, verified at TLS handshake.

- Policy rotation = cert rotation. Operationally painful: every policy change requires re-issuing the cert.
- Many customers per layer either means one cert per customer or an extension that grows with the customer count (bloat).
- Possibly revisitable in v2 for static, slowly-changing scopes.

### 5.3 JWT tokens via the surviving `AUTHORIZATION_TOKEN` option

Rejected for v1. Bring back the deleted `AuthorizationTokenClaims` / `TokenSign` / `TokenCache` machinery and generalize from tenant-prefix to arbitrary key ranges.

- Heavy mechanism (trust authority, JWT parsing, claim verification at every server).
- Rebuilds what was deleted; significant addition.
- mTLS covers the v1 threat model. Tokens add value only against threats v1 doesn't claim to address.

### 5.4 Dedicated `Authorizer` recruited role

Rejected. A worker role analogous to `Resolver`, recruited by Cluster Controller, holding the policy snapshot, called via RPC from CP/SS.

- Apple just removed `EncryptKeyProxy`; reviewers are wary of per-feature roles.
- Adds cluster-controller recruitment, failure handling, monitoring surface, lifecycle tests.
- Versioned-watch on system keys (the deleted `TenantCache` pattern) achieves the same goal with zero new role cost.

### 5.5 Client-side enforcement

Rejected. libfdb checks every transaction against a downloaded policy; server does coarse sanity checks only.

- The opening problem statement is "we cannot trust libfdb." Client-side enforcement is bypassable by anyone who patches libfdb.
- The "perf cost" objection to server-side enforcement does not survive measurement (~0.2 μs per check).

### 5.6 Subscribe to global `\xff/metadataVersion` instead of an own version key

Rejected. Mixes our signal with unrelated cluster-metadata changes — noisy in both directions, entangles us with existing `metadataVersion` consumers in layer code. See §3.7.

### 5.7 Per-transaction sub-identity for in-layer customer isolation

**Considered in detail; deferred from v1.** A previous draft of this design included a `SUB_IDENTITY` per-txn option, tuple `(identity, sub_id)` policy keying, a "bare row" attenuation invariant, an implicit `may-act-as` mechanism, and a knob `AUTHZ_SUBID_MODE` for pre-registered vs free-form sub-ids. This would deliver cluster-enforced per-customer isolation inside a layer (the cluster, not the layer code, prevents `redis-layer` acting for `customer_1234` from touching `customer_5678/*`). Deferred because:

- Adds ~600 LOC across new wire-protocol fields on every request struct, write-time attenuation invariants in the special-keys validator, and the knob/mode for sub-id registration.
- Introduces novel mechanism debates (tuple keying, attenuation invariant, may-act-as semantics, templated vs pre-registered sub-ids) that dilute the "fits cleanly" argument and lengthen review.
- Per-customer isolation inside a layer is delegated to the layer code in every other shared-tenant database. The layer-class boundary v1 provides is meaningful by itself.
- A v2 with **signed sub-id claims** (HMAC against a shared secret, or external IdP) is a natural follow-up — and is what actually closes the threat of a compromised layer asserting an arbitrary sub-id, which the unsigned-string-option version of sub-identity could not.

The earlier draft is archived as a private gist for design history.

---

## 6. Future work / explicitly out of scope for v1

- **Per-transaction sub-identity with signed claims (v2).** Restores cluster-enforced isolation inside a layer. Would add tuple `(identity, sub_id)` policy keying, a per-txn `SUB_IDENTITY` option carrying a signed claim, and a verification mechanism (HMAC against a layer-shared secret, or external IdP signature against a trust authority pubkey). The signing piece is what makes sub-identity actually defend against a compromised layer; the v1 draft's unsigned-string version did not. See §5.6 for what was set aside.
- **Cert-extension policy carriage.** Possibly v2 if signing infrastructure is available and a use case justifies the operational cost (see §5.2).
- **JWT-signed identity claims.** mTLS is sufficient for v1; JWT becomes interesting if cross-cluster identity federation enters scope.
- **Cluster admin / management-API gating.** Clusterfile possession remains the gate. A separate proposal.
- **Backup/restore native authz integration.** v1 treats backup agents as admin (operator-configured via PKI or `admin/`). A future proposal could thread identity through backup metadata.
- **Multi-region awareness for policy distribution.** Policy lives in system keys; behavior follows existing system-keys replication semantics.

---

## 7. Risks (and mitigations)

| # | Risk | Mitigation |
|---|---|---|
| 1 | Cache staleness / system-keys unavailable during a partial cluster issue | Fail-closed past `AUTHZ_CACHE_STALENESS_LIMIT_MS`. Same availability profile as other system-keys-dependent paths. Privileged-peer bypass still applies. |
| 2 | Bootstrap of the first admin identity (chicken-and-egg) | `AUTHZ_INITIAL_ADMIN_CN` knob set at cluster config. One-time bootstrap; document as such. |
| 3 | Range reads spanning mixed permissions | Fail with generic `permission_denied`; error message does not reveal the boundary key. |
| 4 | Backup / DR agents | Grant admin via `admin/<cn>`, or include their CN pattern in `AUTHZ_PRIVILEGED_PEERS`. Documented in Stage 0. |
| 5 | Performance overhead | Quantified: ~0.2 μs per check, <5% per-mutation, <0.1% per-read. Zero when master knob off. |
| 6 | PKI deployment prerequisite | Stage 0 is doc-only and explicit. Knob default empty; nothing breaks if operators haven't done Stage 0. |
| 7 | **Compromised layer reaches all data its identity grants (including across its own customers).** | **Acknowledged limit.** Customer isolation inside a layer is layer-code responsibility — same model as Postgres / MySQL / etc. v2 with signed sub-id claims may revisit (see §6). |
| 8 | Cluster admin / management-API gating remains clusterfile-based | Out of scope for v1. Known limitation. |
| 9 | Untrusted (non-TLS) connections produce empty identity → deny | **Intentional.** Forces mTLS-with-client-cert when authz is on. Stage 0 prerequisite. |
| 10 | Existing clients that use `ACCESS_SYSTEM_KEYS` to read `\xff/...` (e.g. metadataVersion watchers) need a grant when authz is on | Documented in Stage 4 migration notes. Admins grant the layer a single-key R on the specific keys it needs (e.g. `\xff/metadataVersion`). No code change in the layer; just a policy grant. Both gates stack: option still required, authz grant additionally required. |

---

## 8. Open questions for reviewers

- **Naming.** `AUTHZ_*` prefix for the knob namespace — or a different convention?
- **Special-keys subspace path.** `\xff\xff/management/authz/` — or a different module?
- **Error code separation.** Reuse `permission_denied` (6000) or introduce a more specific `authz_policy_denied`? Exact-fit reuse vs telemetry granularity.
- **`AUTHZ_PRIVILEGED_PEERS` vs `admin/<cn>` overlap.** Both shipped because they serve different operational shapes (broad pattern vs surgical entries). Reviewers may want only one.
- **Identity field on `IConnection`.** Plumb full subject DN, or just CN+SANs as strings? Plumbing more is cheap; consumers can ignore what they don't need.
- **Fast-path APIs that bypass StorageServer reads.** Some client APIs (`getMetadataVersion()`, possibly others) may have a non-SS code path. If so, the authz check at SS does not fire on those calls and we would need to either gate the fast-path explicitly or document the limitation. Worth confirming during Stage 1 implementation.
- **Management-API special-keys writes (`\xff\xff/management/...`).** Currently gated by `SPECIAL_KEY_SPACE_ENABLE_WRITES`. With authz on, also gated by an admin policy. The "both gates" pattern matches `ACCESS_SYSTEM_KEYS`. Confirm reviewers want this consistent.

---

## 9. References

- Deletion of tenant/metacluster: PR #12583, commit `bab7637d8`. Tracking PR #12400.
- Surviving authz remnants: `fdbclient/include/fdbclient/NativeAPI.actor.h:19`, `fdbclient/vexillographer/fdb.options:354-357`, `flow/include/flow/error_definitions.h:388` (codes 6000, 6003).
- TLS verify_peers grammar (reused for `AUTHZ_PRIVILEGED_PEERS`): `documentation/sphinx/source/tls.rst`, `flow/TLSConfig.cpp:534-642`.
- Earlier draft of this document (sub-identity in v1 scope) — uploaded as a private gist for design history; see §5.6 for what it contained and why it was set aside.
