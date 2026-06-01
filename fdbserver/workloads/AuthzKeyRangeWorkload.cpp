/*
 * AuthzKeyRangeWorkload.cpp
 *
 * Randomized multi-client per-identity key-range authorization workload (POC v1).
 * See src/design/key-range-authz-v1.md.
 *
 * Each workload clientId runs on its own simulated tester process, and that process presents ONE
 * fixed identity (`ProcessInfo::simPeerIdentity`) for its entire life — set once in the constructor,
 * never switched. This mirrors a real client holding a single mTLS cert: identity is bound
 * per-connection at establishment, so switching it mid-run would leave stale-identity connections
 * behind (enforcement leak + consistency-check hang).
 *
 * clientId 0 acts as **admin** (its fixed identity == AUTHZ_INITIAL_ADMIN_CN): in setup() it writes a
 * policy granting each non-admin client `client-<i>` RW over its own keyspace ["k<i>/", "k<i>0"). The
 * tester framework runs ALL clients' setup() before ANY start(), and the policy is broadcast + applied
 * version-consistently, so by start() every grant is in force.
 *
 * In start(), each client issues a randomized mix of get / getRange / set / clear:
 *   - clientId 0 (admin): operates across keyspaces; every op MUST succeed (validates admin bypass).
 *   - clientId i>0 (client-<i>): most ops target its OWN keyspace (expect allow); the rest target a
 *     random OTHER client's keyspace (expect permission_denied). The first two ops are forced
 *     (one cross, one own) so both paths are always exercised.
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
		// Each client process presents ONE fixed identity for its whole life, set here before it opens
		// any connection — exactly like a real client holding a single mTLS cert. We must NOT switch it
		// mid-run: identity is bound per-connection at establishment, so a later switch would leave
		// stale-identity connections behind (cross-op enforcement leak + consistency-check hang).
		setPresentedIdentity(myCN);
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

	// Sim-only: set the identity this (tester) process presents to peers. Empty clears it.
	void setPresentedIdentity(std::string const& cn) {
		ASSERT(g_network->isSimulated());
		auto* p = g_simulator->getCurrentProcess();
		if (cn.empty()) {
			p->simPeerIdentity = Optional<std::string>();
		} else {
			p->simPeerIdentity = cn;
		}
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
			ok = ok && adminOpsOk > 0;
		} else {
			ok = ok && ownOpsOk > 0 && crossDeniedOk > 0;
		}
		if (!ok) {
			TraceEvent(SevError, "AuthzKeyRangeWorkloadFailed")
			    .detail("ClientId", clientId)
			    .detail("Identity", myCN)
			    .detail("SawViolation", sawViolation)
			    .detail("OwnOpsOk", ownOpsOk)
			    .detail("CrossDeniedOk", crossDeniedOk)
			    .detail("AdminOpsOk", adminOpsOk);
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

	// clientId 0 writes one policy row per non-admin client, granting it RW on its own keyspace.
	// (clientId 0 already presents the admin identity for its whole life — set in the constructor.)
	Future<Void> runSetup(Database cx) {
		Transaction tr(cx);
		while (true) {
			Error err;
			try {
				tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
				tr.setOption(FDBTransactionOptions::LOCK_AWARE);
				for (int i = 1; i < clientCount; i++) {
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
		TraceEvent(SevInfo, "AuthzWorkloadPoliciesWritten").detail("NonAdminClients", clientCount - 1);
	}

	Future<Void> runStart(Database cx) {
		// Identity was fixed once in the constructor (myCN) — no mid-run switching.
		TraceEvent(SevInfo, "AuthzWorkloadClientStart")
		    .detail("ClientId", clientId)
		    .detail("Identity", myCN)
		    .detail("IsAdmin", isAdmin)
		    .detail("ClientCount", clientCount);

		for (int op = 0; op < opsPerClient; op++) {
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
					goElsewhere = false; // force one own-keyspace op (expect allow)
				} else {
					goElsewhere = deterministicRandom()->random01() < crossProbability;
				}
				target = goElsewhere ? randomOtherClient() : clientId;
				expectAllowed = !goElsewhere;
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
