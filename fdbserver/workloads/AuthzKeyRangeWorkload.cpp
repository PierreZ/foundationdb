/*
 * AuthzKeyRangeWorkload.cpp
 *
 * Randomized multi-client per-identity key-range authorization workload (POC v2).
 * See src/design/key-range-authz-v2.md (incl. addendum).
 *
 * Each workload clientId runs on its own simulated tester process, and that process is ISSUED one
 * fixed identity (`ProcessInfo::issueIdentity`, write-once) for its entire life in the constructor.
 * This mirrors a real client holding a single ops-issued mTLS cert: identity is bound for the
 * process's life, so presenting a forged identity or switching mid-run — which would leave
 * stale-identity connections behind — is structurally impossible.
 *
 * clientId 0 acts as **admin** (its fixed identity == AUTHZ_INITIAL_ADMIN_CN): in setup() it writes a
 * policy granting each granted client `client-<i>` RW over its own keyspace ["k<i>/", "k<i>0"),
 * bounded by AUTHZ_MAX_IDENTITIES (sim-randomized 4..32), fills the identity map to exactly the cap,
 * and asserts the (cap+1)'th identity is rejected with authz_too_many_identities. The tester
 * framework runs ALL clients' setup() before ANY start(), and the policy is broadcast + applied
 * version-consistently, so by start() every grant is in force.
 *
 * In start(), each client issues a randomized mix of get / getRange / set / clear, spread over sim
 * time so the injected failure workloads (machine kills/reboots) overlap the run — every op after an
 * SS reboot exercises the policy map restored from persistAuthzPolicyKeys:
 *   - clientId 0 (admin): operates across keyspaces; every op MUST succeed (validates admin bypass).
 *   - granted clientId i>0 (client-<i>): most ops target its OWN keyspace (expect allow); the rest
 *     target a random OTHER client's keyspace (expect permission_denied). The first two ops are
 *     forced (one cross, one own) so both paths are always exercised.
 *   - un-granted clients (beyond the cap): every op must be denied.
 * Wrong outcomes raise SevError. The post-test ConsistencyCheck is disabled in the toml: it would run
 * on these non-admin tester processes (a full-keyspace scan is an ops/admin operation, not a layer
 * client's job).
 */

#include <string>

#include "fdbclient/AuthzPolicy.h"
#include "fdbclient/FDBOptions.g.h"
#include "fdbclient/NativeAPI.actor.h"
#include "fdbclient/SystemData.h"
#include "fdbrpc/simulator.h"
#include "fdbrpc/SimulatorProcessInfo.h"
#include "fdbserver/core/Knobs.h"
#include "fdbserver/core/TesterInterface.h"
#include "fdbserver/tester/workloads.h"
#include "flow/Trace.h"

struct AuthzKeyRangeWorkload : TestWorkload {
	static constexpr auto NAME = "AuthzKeyRange";

	int opsPerClient;
	double crossProbability;
	std::string adminCN; // == AUTHZ_INITIAL_ADMIN_CN
	std::string myCN; // this client's presented identity
	bool isAdmin;
	int grantedCount; // clients 1..grantedCount have a policy row (bounded by AUTHZ_MAX_IDENTITIES)
	bool granted; // this client has a policy row; un-granted clients must be denied everywhere
	bool capRejectionOk = false; // admin: creating the (cap+1)'th identity was rejected

	// Outcome tracking (per client; check() validates this client's own state).
	int64_t ownOpsOk = 0; // own-keyspace ops that were correctly allowed (non-admin)
	int64_t crossDeniedOk = 0; // cross-keyspace ops that were correctly denied (non-admin)
	int64_t adminOpsOk = 0; // ops correctly allowed for the admin client
	bool sawViolation = false; // any op whose allow/deny outcome was wrong

	explicit AuthzKeyRangeWorkload(WorkloadContext const& wcx) : TestWorkload(wcx) {
		opsPerClient = getOption(options, "opsPerClient"_sr, 30);
		crossProbability = getOption(options, "crossProbability"_sr, 0.25);
		adminCN = SERVER_KNOBS->AUTHZ_INITIAL_ADMIN_CN;
		isAdmin = (clientId == 0);
		myCN = isAdmin ? adminCN : ("client-" + std::to_string(clientId));
		// The identity cap may be sim-randomized (4..32); only the first grantedCount clients get a
		// policy row. Clients above the cap run un-granted and expect deny on every op.
		grantedCount = std::min(clientCount - 1, SERVER_KNOBS->AUTHZ_MAX_IDENTITIES);
		granted = !isAdmin && clientId <= grantedCount;
		// Each client process is ISSUED one fixed identity for its whole life, before it opens any
		// connection — exactly like a real client holding a single mTLS cert. issueIdentity is
		// write-once (ASSERT on re-issue with a different CN), so a mid-run switch — which would
		// leave stale-identity connections behind — is structurally impossible.
		ASSERT(g_network->isSimulated());
		g_simulator->getCurrentProcess()->issueIdentity(myCN);
	}

	// --- key helpers: client c owns ["k<c>/", "k<c>0") ('/'=0x2f < '0'=0x30) ---
	Key keyspaceBegin(int c) const {
		std::string s = "k" + std::to_string(c) + "/";
		return Key(StringRef(s));
	}
	Key keyspaceEnd(int c) const {
		std::string s = "k" + std::to_string(c) + "0";
		return Key(StringRef(s));
	}
	Key keyFor(int c, int idx) const {
		std::string s = "k" + std::to_string(c) + "/" + format("%06d", idx);
		return Key(StringRef(s));
	}

	int randomOtherClient() const {
		// Any client index != clientId (including 0 — this client has no grant for the admin's
		// notional keyspace, so targeting it is a valid "denied" probe).
		int j = deterministicRandom()->randomInt(0, clientCount);
		if (j == clientId) {
			j = (j + 1) % clientCount;
		}
		return j;
	}

	Future<Void> setup(Database const& cx) override {
		if (clientId != 0) {
			return Void();
		}
		return runSetup(cx);
	}

	Future<Void> start(Database const& cx) override { return runStart(cx); }

	Future<bool> check(Database const& cx) override {
		bool ok = !sawViolation;
		if (isAdmin) {
			ok = ok && adminOpsOk > 0 && capRejectionOk;
		} else if (granted) {
			ok = ok && ownOpsOk > 0 && crossDeniedOk > 0;
		} else {
			ok = ok && crossDeniedOk > 0;
		}
		if (!ok) {
			TraceEvent(SevError, "AuthzKeyRangeWorkloadFailed")
			    .detail("ClientId", clientId)
			    .detail("Identity", myCN)
			    .detail("Granted", granted)
			    .detail("SawViolation", sawViolation)
			    .detail("OwnOpsOk", ownOpsOk)
			    .detail("CrossDeniedOk", crossDeniedOk)
			    .detail("AdminOpsOk", adminOpsOk)
			    .detail("CapRejectionOk", capRejectionOk);
		} else {
			TraceEvent(SevInfo, "AuthzKeyRangeWorkloadPassed")
			    .detail("ClientId", clientId)
			    .detail("Identity", myCN)
			    .detail("OwnOpsOk", ownOpsOk)
			    .detail("CrossDeniedOk", crossDeniedOk)
			    .detail("AdminOpsOk", adminOpsOk);
		}
		return ok;
	}

	void getMetrics(std::vector<PerfMetric>& m) override {
		m.emplace_back("OwnOpsOk", ownOpsOk, Averaged::False);
		m.emplace_back("CrossDeniedOk", crossDeniedOk, Averaged::False);
		m.emplace_back("AdminOpsOk", adminOpsOk, Averaged::False);
	}

	// clientId 0 (admin) writes one policy row per granted client (RW on its own keyspace), fills
	// the identity map to exactly AUTHZ_MAX_IDENTITIES with empty filler rows, then probes the cap:
	// creating one more identity must fail with authz_too_many_identities.
	Future<Void> runSetup(Database cx) {
		// 1. Grants for clients 1..grantedCount (bounded by the — possibly randomized — cap).
		{
			Transaction tr(cx);
			while (true) {
				Error err;
				try {
					tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
					tr.setOption(FDBTransactionOptions::LOCK_AWARE);
					for (int i = 1; i <= grantedCount; i++) {
						authz::PolicyEntry e;
						e.grants.push_back(authz::Grant(keyspaceBegin(i), keyspaceEnd(i), authz::Perm::W));
						std::string id = "client-" + std::to_string(i);
						tr.set(authzPolicyKeyFor(StringRef(id)), e.encode());
					}
					co_await tr.commit();
					break;
				} catch (Error& e) {
					err = e;
				}
				co_await tr.onError(err);
			}
		}
		TraceEvent(SevInfo, "AuthzWorkloadPoliciesWritten")
		    .detail("GrantedClients", grantedCount)
		    .detail("UngrantedClients", clientCount - 1 - grantedCount)
		    .detail("MaxIdentities", SERVER_KNOBS->AUTHZ_MAX_IDENTITIES);

		// 2. Fill the map to exactly AUTHZ_MAX_IDENTITIES identities (empty grants).
		int fillers = SERVER_KNOBS->AUTHZ_MAX_IDENTITIES - grantedCount;
		if (fillers > 0) {
			Transaction tr(cx);
			while (true) {
				Error err;
				try {
					tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
					tr.setOption(FDBTransactionOptions::LOCK_AWARE);
					for (int j = 0; j < fillers; j++) {
						std::string id = "cap-filler-" + std::to_string(j);
						tr.set(authzPolicyKeyFor(StringRef(id)), authz::PolicyEntry().encode());
					}
					co_await tr.commit();
					break;
				} catch (Error& e) {
					err = e;
				}
				co_await tr.onError(err);
			}
		}

		// 3. The (cap+1)'th identity must be rejected. Updates to existing identities still work —
		//    every later policy write in this test touches existing rows only.
		{
			Transaction tr(cx);
			while (true) {
				Error err;
				try {
					tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
					tr.setOption(FDBTransactionOptions::LOCK_AWARE);
					tr.set(authzPolicyKeyFor("cap-overflow"_sr), authz::PolicyEntry().encode());
					co_await tr.commit();
					TraceEvent(SevError, "AuthzWorkloadCapNotEnforced")
					    .detail("MaxIdentities", SERVER_KNOBS->AUTHZ_MAX_IDENTITIES);
					sawViolation = true;
					break;
				} catch (Error& e) {
					err = e;
				}
				if (err.code() == error_code_authz_too_many_identities) {
					capRejectionOk = true;
					break; // the cap decision is final — do not retry
				}
				co_await tr.onError(err);
			}
		}
		TraceEvent(SevInfo, "AuthzWorkloadCapProbe")
		    .detail("CapRejectionOk", capRejectionOk)
		    .detail("MaxIdentities", SERVER_KNOBS->AUTHZ_MAX_IDENTITIES);
	}

	Future<Void> runStart(Database cx) {
		// Identity was fixed once in the constructor (myCN) — no mid-run switching.
		TraceEvent(SevInfo, "AuthzWorkloadClientStart")
		    .detail("ClientId", clientId)
		    .detail("Identity", myCN)
		    .detail("IsAdmin", isAdmin)
		    .detail("ClientCount", clientCount);

		for (int op = 0; op < opsPerClient; op++) {
			// Spread the ops over sim time so they overlap the injected failure workloads' machine
			// kills/reboots — every op after an SS reboot exercises the restored policy map.
			co_await delay(0.5 + deterministicRandom()->random01());
			int target;
			bool expectAllowed;
			if (isAdmin) {
				// Admin operates anywhere; everything must be allowed.
				target = clientCount > 1 ? deterministicRandom()->randomInt(1, clientCount) : 0;
				expectAllowed = true;
			} else {
				bool goElsewhere;
				if (op == 0) {
					goElsewhere = true; // force one cross-keyspace probe (expect deny)
				} else if (op == 1) {
					goElsewhere = false; // force one own-keyspace op
				} else {
					goElsewhere = deterministicRandom()->random01() < crossProbability;
				}
				target = goElsewhere ? randomOtherClient() : clientId;
				// An un-granted client (beyond the identity cap) must be denied everywhere.
				expectAllowed = !goElsewhere && granted;
			}
			co_await doRandomOp(cx, target, expectAllowed);
		}
		// No reset: this process keeps its fixed identity for life (like a real client's cert).
	}

	Future<Void> doRandomOp(Database cx, int target, bool expectAllowed) {
		int idx = deterministicRandom()->randomInt(0, 1000);
		Key k = keyFor(target, idx);
		int opType = deterministicRandom()->randomInt(0, 4); // 0 get, 1 getRange, 2 set, 3 clear
		Key kEnd = keyFor(target, idx + 10);
		Transaction tr(cx);
		while (true) {
			Error err;
			try {
				tr.setOption(FDBTransactionOptions::LOCK_AWARE);
				if (opType == 0) {
					Optional<Value> v = co_await tr.get(k);
					(void)v;
				} else if (opType == 1) {
					RangeResult r = co_await tr.getRange(KeyRangeRef(k, kEnd), 10);
					(void)r;
				} else if (opType == 2) {
					std::string v = deterministicRandom()->randomAlphaNumeric(8);
					tr.set(k, StringRef(v));
					co_await tr.commit();
				} else {
					tr.clear(k);
					co_await tr.commit();
				}
				// Operation succeeded.
				if (!expectAllowed) {
					TraceEvent(SevError, "AuthzWorkloadExpectedDenyButAllowed")
					    .detail("ClientId", clientId)
					    .detail("Identity", myCN)
					    .detail("Target", target)
					    .detail("Key", k)
					    .detail("OpType", opType);
					sawViolation = true;
				} else if (isAdmin) {
					++adminOpsOk;
				} else {
					++ownOpsOk;
				}
				co_return;
			} catch (Error& e) {
				err = e;
			}
			if (err.code() == error_code_permission_denied) {
				if (expectAllowed) {
					TraceEvent(SevError, "AuthzWorkloadExpectedAllowButDenied")
					    .detail("ClientId", clientId)
					    .detail("Identity", myCN)
					    .detail("Target", target)
					    .detail("Key", k)
					    .detail("OpType", opType);
					sawViolation = true;
				} else {
					++crossDeniedOk;
				}
				co_return; // an authorization decision is final — do not retry
			}
			co_await tr.onError(err); // retryable error (not_committed, transaction_too_old, …)
		}
	}
};

WorkloadFactory<AuthzKeyRangeWorkload> AuthzKeyRangeWorkloadFactory;
