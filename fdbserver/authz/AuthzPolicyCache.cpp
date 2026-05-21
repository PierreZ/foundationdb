/*
 * AuthzPolicyCache.cpp
 *
 * Per-identity key-range authorization policy cache (POC).
 * See src/design/key-range-authz.md.
 */

#include "fdbserver/authz/AuthzPolicyCache.h"

#include <algorithm>
#include <cstring>

#include "fdbclient/CommitProxyInterface.h"
#include "fdbclient/ReadYourWrites.h"
#include "fdbclient/SystemData.h"
#include "fdbserver/core/Knobs.h"
#include "flow/Error.h"
#include "flow/Trace.h"
#include "flow/genericactors.actor.h"
#include "flow/serialize.h"

namespace authz {

const KeyRangeRef authzKeys("\xff/authz/"_sr, "\xff/authz0"_sr);
const KeyRef authzVersionKey = "\xff/authz/version"_sr;
const KeyRangeRef authzPolicyKeys("\xff/authz/policy/"_sr, "\xff/authz/policy0"_sr);
const KeyRangeRef authzAdminKeys("\xff/authz/admin/"_sr, "\xff/authz/admin0"_sr);

// ---------- Encoding ----------

Value encodePolicyValue(std::vector<Grant> const& grants) {
	BinaryWriter wr(Unversioned());
	uint32_t n = static_cast<uint32_t>(grants.size());
	wr << n;
	for (auto const& g : grants) {
		uint32_t bn = static_cast<uint32_t>(g.begin.size());
		wr << bn;
		wr.serializeBytes(g.begin);
		uint32_t en = static_cast<uint32_t>(g.end.size());
		wr << en;
		wr.serializeBytes(g.end);
		uint8_t p = static_cast<uint8_t>(g.perm);
		wr << p;
	}
	return wr.toValue();
}

std::vector<Grant> decodePolicyValue(ValueRef const& v) {
	std::vector<Grant> out;
	BinaryReader rd(v, Unversioned());
	uint32_t n = 0;
	rd >> n;
	out.reserve(n);
	for (uint32_t i = 0; i < n; ++i) {
		uint32_t bn = 0;
		rd >> bn;
		Standalone<StringRef> begin = makeString(bn);
		rd.serializeBytes(mutateString(begin), bn);
		uint32_t en = 0;
		rd >> en;
		Standalone<StringRef> end = makeString(en);
		rd.serializeBytes(mutateString(end), en);
		uint8_t p = 0;
		rd >> p;
		out.push_back(Grant{ Key(begin), Key(end), static_cast<Perm>(p) });
	}
	return out;
}

// ---------- Cache ----------

AuthzPolicyCache::AuthzPolicyCache() : lastRefresh(0.0), everRefreshed(false) {}

bool AuthzPolicyCache::isFresh() const {
	if (!everRefreshed) {
		return false;
	}
	double limit = SERVER_KNOBS->AUTHZ_CACHE_STALENESS_LIMIT_MS / 1000.0;
	return (now() - lastRefresh) <= limit;
}

bool AuthzPolicyCache::isAdmin(std::string const& identity) const {
	if (identity.empty()) {
		return false;
	}
	if (!SERVER_KNOBS->AUTHZ_INITIAL_ADMIN_CN.empty() &&
	    identity == SERVER_KNOBS->AUTHZ_INITIAL_ADMIN_CN) {
		return true;
	}
	return admins.find(identity) != admins.end();
}

static bool permCovers(Perm granted, Perm requested) {
	if (granted == Perm::Denied) {
		return false;
	}
	if (requested == Perm::R) {
		return granted == Perm::R || granted == Perm::W;
	}
	if (requested == Perm::W) {
		return granted == Perm::W;
	}
	return false;
}

bool AuthzPolicyCache::checkAgainstGrants(std::vector<Grant> const& grants,
                                          KeyRef begin,
                                          KeyRef end,
                                          Perm op) const {
	// POC: linear scan. v1 would binary-search; range list size is expected to be O(10-100).
	for (auto const& g : grants) {
		// Grant range must fully cover [begin, end).
		if (g.begin <= begin && end <= g.end) {
			return permCovers(g.perm, op);
		}
	}
	return false;
}

bool AuthzPolicyCache::check(bool isTrustedPeer,
                             std::string const& identity,
                             KeyRef key,
                             Perm op) const {
	// Master-knob fast path; the call site also guards, but defense-in-depth.
	if (!SERVER_KNOBS->AUTHZ_ENFORCEMENT_ENABLED) {
		return true;
	}
	// POC: system keys (\xff/...) are gated solely by ACCESS_SYSTEM_KEYS (the existing
	// mechanism). The design's full v1 layers authz on top, but POC needs cluster-internal
	// services to read system keys freely without relying on trust-bit propagation through
	// every code path. See src/design/key-range-authz.md §0 (POC scope).
	if (key.size() > 0 && key[0] == static_cast<uint8_t>(0xff)) {
		return true;
	}
	if (isTrustedPeer) {
		return true;
	}
	if (identity.empty()) {
		return false;
	}
	if (isAdmin(identity)) {
		return true;
	}
	if (!isFresh()) {
		return false;
	}
	auto it = policy.find(identity);
	if (it == policy.end()) {
		return false;
	}
	// Point check: treat as a degenerate range [key, key + \x00).
	std::string endBuf(reinterpret_cast<const char*>(key.begin()), key.size());
	endBuf.push_back('\x00');
	return checkAgainstGrants(it->second, key, StringRef(endBuf), op);
}

bool AuthzPolicyCache::checkRange(bool isTrustedPeer,
                                  std::string const& identity,
                                  KeyRef begin,
                                  KeyRef end,
                                  Perm op) const {
	if (!SERVER_KNOBS->AUTHZ_ENFORCEMENT_ENABLED) {
		return true;
	}
	// POC: system keys bypass — see check() for rationale.
	if (begin.size() > 0 && begin[0] == static_cast<uint8_t>(0xff)) {
		return true;
	}
	if (isTrustedPeer) {
		return true;
	}
	if (identity.empty()) {
		return false;
	}
	if (isAdmin(identity)) {
		return true;
	}
	if (!isFresh()) {
		return false;
	}
	auto it = policy.find(identity);
	if (it == policy.end()) {
		return false;
	}
	return checkAgainstGrants(it->second, begin, end, op);
}

void AuthzPolicyCache::markRefreshed(Standalone<StringRef> version) {
	snapshotVersion = version;
	lastRefresh = now();
	everRefreshed = true;
}

void AuthzPolicyCache::rebuildFromSnapshot(RangeResult const& policyRows,
                                            RangeResult const& adminRows) {
	policy.clear();
	for (auto const& kv : policyRows) {
		if (!authzPolicyKeys.contains(kv.key)) {
			continue;
		}
		StringRef identity = kv.key.removePrefix(authzPolicyKeys.begin);
		std::string idStr(reinterpret_cast<const char*>(identity.begin()), identity.size());
		policy.emplace(std::move(idStr), decodePolicyValue(kv.value));
	}
	admins.clear();
	for (auto const& kv : adminRows) {
		if (!authzAdminKeys.contains(kv.key)) {
			continue;
		}
		StringRef identity = kv.key.removePrefix(authzAdminKeys.begin);
		admins.emplace(reinterpret_cast<const char*>(identity.begin()), identity.size());
	}
}

namespace {

Future<Void> runMonitor(AuthzPolicyCache* self, Database cx) {
	Transaction tr(cx);
	Standalone<StringRef> lastVersion;
	bool haveLastVersion = false;
	double sleepSec = std::max(0.5, (SERVER_KNOBS->AUTHZ_CACHE_STALENESS_LIMIT_MS / 1000.0) / 3.0);
	for (;;) {
		Error caught(0);
		try {
			tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr.setOption(FDBTransactionOptions::LOCK_AWARE);
			Optional<Value> verVal = co_await tr.get(authzVersionKey);
			Standalone<StringRef> current =
			    verVal.present() ? Standalone<StringRef>(verVal.get()) : Standalone<StringRef>();
			bool changed = !haveLastVersion || current != lastVersion;
			if (changed) {
				RangeResult policyRows =
				    co_await tr.getRange(authzPolicyKeys, GetRangeLimits::ROW_LIMIT_UNLIMITED);
				RangeResult adminRows =
				    co_await tr.getRange(authzAdminKeys, GetRangeLimits::ROW_LIMIT_UNLIMITED);
				self->rebuildFromSnapshot(policyRows, adminRows);
				lastVersion = current;
				haveLastVersion = true;
				TraceEvent(SevInfo, "AuthzPolicyCacheRefreshed")
				    .detail("PolicyRows", policyRows.size())
				    .detail("AdminRows", adminRows.size());
			}
			self->markRefreshed(current);
			tr.reset();
		} catch (Error& e) {
			caught = e;
		}
		if (caught.code() == error_code_actor_cancelled) {
			throw caught;
		}
		if (caught.code() != 0) {
			TraceEvent(SevWarn, "AuthzPolicyCacheRefreshError").errorUnsuppressed(caught).suppressFor(1.0);
			// Best-effort onError; swallow non-retriable errors so the cache stays alive.
			// The cache being stale (fail-closed past AUTHZ_CACHE_STALENESS_LIMIT_MS) is the
			// fallback if refresh stays broken — but the cache should NEVER kill its host.
			try {
				co_await tr.onError(caught);
			} catch (Error& e2) {
				if (e2.code() == error_code_actor_cancelled) {
					throw;
				}
				tr.reset();
			}
			co_await delay(sleepSec);
			continue;
		}
		co_await delay(sleepSec);
	}
}

} // namespace

Future<Void> AuthzPolicyCache::run(Database cx) {
	return runMonitor(this, cx);
}

} // namespace authz
