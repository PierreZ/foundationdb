/*
 * AuthzKeyRangeWorkload.cpp
 *
 * POC end-to-end check for per-identity key-range authorization (v1).
 * See src/design/key-range-authz-v1.md.
 *
 * Scenario (single-client):
 *   1. As the admin identity, commit a policy granting a freshly-generated reader CN R access to
 *      ["k", "kz"). Writing \xff/authz/policy/<reader> requires admin; the CommitProxy recognizes
 *      it as a metadata mutation and broadcasts it (privatized) to every StorageServer, which apply
 *      it in version order — no version key, no polling.
 *   2. From the reader CN: read "k1" → expect success; read "z1" (outside grant) → permission_denied.
 *   3. From a second, unknown CN (no policy row): read "k1" → permission_denied.
 *
 * Simulation identity injection: this workload sets its own simulated process's explicit
 * `simPeerIdentity` field (NOT the placement locality) to switch the identity it presents between
 * phases. Sim2Conn mints a real X509 with that CN and surfaces it as the peer's TLS CN, exactly as
 * production sources the CN from the verified client cert.
 */

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

namespace {

const std::string kAdminCN = "test-admin";

// Switch the identity this (tester) process presents to peers. Explicit sim-only flag — replaces
// v0's peer_cert_identity locality poke. Empty clears it (no client cert). See key-range-authz-v1.md.
void setPresentedIdentity(std::string const& cn) {
	ASSERT(g_network->isSimulated());
	auto* process = g_simulator->getCurrentProcess();
	if (cn.empty()) {
		process->simPeerIdentity = Optional<std::string>();
	} else {
		process->simPeerIdentity = cn;
	}
}

} // namespace

struct AuthzKeyRangeWorkload : TestWorkload {
	static constexpr auto NAME = "AuthzKeyRange";

	bool setupOk = false;
	bool readerAllowedOk = false;
	bool readerDeniedOk = false;
	bool unknownDeniedOk = false;

	// Generated per run so Joshua ensembles exercise distinct identities.
	std::string readerCN;
	std::string unknownCN;

	explicit AuthzKeyRangeWorkload(WorkloadContext const& wcx) : TestWorkload(wcx) {
		readerCN = "reader-" + deterministicRandom()->randomUniqueID().shortString();
		unknownCN = "unknown-" + deterministicRandom()->randomUniqueID().shortString();
	}

	Future<Void> setup(Database const& cx) override {
		if (clientId != 0) {
			return Void();
		}
		return runSetup(cx, this);
	}

	Future<Void> start(Database const& cx) override {
		if (clientId != 0) {
			return Void();
		}
		return runStart(cx, this);
	}

	Future<bool> check(Database const& cx) override {
		if (clientId != 0) {
			return true;
		}
		bool ok = setupOk && readerAllowedOk && readerDeniedOk && unknownDeniedOk;
		if (!ok) {
			TraceEvent(SevError, "AuthzKeyRangeWorkloadFailed")
			    .detail("SetupOk", setupOk)
			    .detail("ReaderAllowedOk", readerAllowedOk)
			    .detail("ReaderDeniedOk", readerDeniedOk)
			    .detail("UnknownDeniedOk", unknownDeniedOk);
		}
		return ok;
	}

	void getMetrics(std::vector<PerfMetric>& m) override {}

	static Future<Void> runSetup(Database cx, AuthzKeyRangeWorkload* self) {
		// Act as admin (the knob-bootstrapped identity) to write the policy via system keys.
		setPresentedIdentity(kAdminCN);

		authz::PolicyEntry entry;
		entry.grants.push_back(authz::Grant("k"_sr, "kz"_sr, authz::Perm::R));
		Value policyValue = entry.encode();
		Key policyKey = authzPolicyKeyFor(StringRef(self->readerCN));

		Transaction tr(cx);
		bool committed = false;
		while (!committed) {
			tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			tr.set(policyKey, policyValue);
			Error caught(0);
			try {
				co_await tr.commit();
				committed = true;
			} catch (Error& e) {
				caught = e;
			}
			if (caught.code() != 0) {
				co_await tr.onError(caught);
			}
		}
		self->setupOk = true;

		// The policy mutation is broadcast + applied at every SS in version order with the commit, so
		// a read at a version >= the commit version already sees it. A short delay is belt-and-suspenders.
		co_await delay(2.0);

		TraceEvent(SevInfo, "AuthzKeyRangeWorkloadSetupDone").detail("ReaderCN", self->readerCN);
	}

	static Future<Void> runStart(Database cx, AuthzKeyRangeWorkload* self) {
		// Reader, allowed: read "k1" should succeed.
		setPresentedIdentity(self->readerCN);
		{
			Transaction tr(cx);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			try {
				Optional<Value> v = co_await tr.get("k1"_sr);
				(void)v;
				self->readerAllowedOk = true;
			} catch (Error& e) {
				TraceEvent(SevError, "AuthzKeyRangeWorkloadReaderAllowedUnexpectedError").error(e);
			}
		}

		// Reader, denied: read "z1" is outside the grant.
		setPresentedIdentity(self->readerCN);
		{
			Transaction tr(cx);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			try {
				Optional<Value> v = co_await tr.get("z1"_sr);
				(void)v;
				TraceEvent(SevError, "AuthzKeyRangeWorkloadReaderDeniedReturnedValue");
			} catch (Error& e) {
				if (e.code() == error_code_permission_denied) {
					self->readerDeniedOk = true;
				} else {
					TraceEvent(SevError, "AuthzKeyRangeWorkloadReaderDeniedUnexpectedError").error(e);
				}
			}
		}

		// Unknown identity, denied: read "k1" with no policy row should fail.
		setPresentedIdentity(self->unknownCN);
		{
			Transaction tr(cx);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			try {
				Optional<Value> v = co_await tr.get("k1"_sr);
				(void)v;
				TraceEvent(SevError, "AuthzKeyRangeWorkloadUnknownReturnedValue");
			} catch (Error& e) {
				if (e.code() == error_code_permission_denied) {
					self->unknownDeniedOk = true;
				} else {
					TraceEvent(SevError, "AuthzKeyRangeWorkloadUnknownUnexpectedError").error(e);
				}
			}
		}

		// Reset to admin so any teardown traffic this process issues is allowed.
		setPresentedIdentity(kAdminCN);
	}
};

WorkloadFactory<AuthzKeyRangeWorkload> AuthzKeyRangeWorkloadFactory;
