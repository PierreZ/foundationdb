/*
 * AuthzKeyRangeWorkload.cpp
 *
 * POC end-to-end check for per-identity key-range authorization.
 * See src/design/key-range-authz.md.
 *
 * Scenario (single-client):
 *   1. As the admin identity, write a policy granting "test-reader" R access to ["k", "kz").
 *      Bump the version key so the cache picks the change up.
 *   2. Wait for the cache refresh interval.
 *   3. From the "test-reader" identity: read "k1" → expect success; read "z1" (outside grant)
 *      → expect permission_denied.
 *   4. From an "unknown-id" identity: read "k1" → expect permission_denied.
 *
 * Simulation identity injection: this workload sets its own simulated process's
 * `peer_cert_identity` locality key to switch identities between phases. Sim2Conn surfaces
 * that as the peer's TLS CN. Production would source the CN from the verified X509 cert.
 */

#include "fdbclient/FDBOptions.g.h"
#include "fdbclient/NativeAPI.actor.h"
#include "fdbclient/ReadYourWrites.h"
#include "fdbrpc/simulator.h"
#include "fdbrpc/SimulatorProcessInfo.h"
#include "fdbserver/authz/AuthzPolicyCache.h"
#include "fdbserver/core/Knobs.h"
#include "fdbserver/core/TesterInterface.h"
#include "fdbserver/tester/workloads.h"
#include "flow/Trace.h"

namespace {

const std::string kAdminCN = "test-admin";
const std::string kReaderCN = "test-reader";
const std::string kUnknownCN = "unknown-id";

void setSimulatedIdentity(std::string const& cn) {
	ASSERT(g_network->isSimulated());
	auto* process = g_simulator->getCurrentProcess();
	if (cn.empty()) {
		process->locality.set("peer_cert_identity"_sr, Optional<Standalone<StringRef>>());
	} else {
		process->locality.set("peer_cert_identity"_sr, Standalone<StringRef>(StringRef(cn)));
	}
}

Key policyKey(std::string const& identity) {
	std::string s = "\xff/authz/policy/";
	s.append(identity);
	return Key(StringRef(s));
}

const KeyRef authzVersionKey = "\xff/authz/version"_sr;

} // namespace

struct AuthzKeyRangeWorkload : TestWorkload {
	static constexpr auto NAME = "AuthzKeyRange";

	bool setupOk = false;
	bool readerAllowedOk = false;
	bool readerDeniedOk = false;
	bool unknownDeniedOk = false;

	explicit AuthzKeyRangeWorkload(WorkloadContext const& wcx) : TestWorkload(wcx) {}

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
		// Act as admin to write the policy directly via system keys.
		setSimulatedIdentity(kAdminCN);

		std::vector<authz::Grant> grants;
		grants.push_back(authz::Grant{ Key("k"_sr), Key("kz"_sr), authz::Perm::R });
		Value policyValue = authz::encodePolicyValue(grants);

		Transaction tr(cx);
		bool committed = false;
		while (!committed) {
			tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			tr.set(policyKey(kReaderCN), policyValue);
			// Bump the version key. The byte content doesn't matter for the POC — the cache
			// refreshes whenever the value changes; any new bytes suffice.
			tr.set(authzVersionKey, "v1"_sr);
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

		// Wait for both proxy and storage server caches to refresh from the version bump.
		double refreshSec = std::max(0.5, (SERVER_KNOBS->AUTHZ_CACHE_STALENESS_LIMIT_MS / 1000.0) / 3.0);
		co_await delay(refreshSec * 4.0 + 2.0);

		TraceEvent(SevInfo, "AuthzKeyRangeWorkloadSetupDone");
	}

	static Future<Void> runStart(Database cx, AuthzKeyRangeWorkload* self) {
		// Reader, allowed: read "k1" should succeed.
		setSimulatedIdentity(kReaderCN);
		{
			Transaction tr(cx);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			Error caught(0);
			try {
				Optional<Value> v = co_await tr.get("k1"_sr);
				(void)v;
				self->readerAllowedOk = true;
			} catch (Error& e) {
				caught = e;
				TraceEvent(SevError, "AuthzKeyRangeWorkloadReaderAllowedUnexpectedError").error(e);
			}
			(void)caught;
		}

		// Reader, denied: read "z1" is outside the grant.
		setSimulatedIdentity(kReaderCN);
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
		setSimulatedIdentity(kUnknownCN);
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

		// Reset to admin (best-effort) so any teardown traffic is allowed.
		setSimulatedIdentity(kAdminCN);
	}
};

WorkloadFactory<AuthzKeyRangeWorkload> AuthzKeyRangeWorkloadFactory;
