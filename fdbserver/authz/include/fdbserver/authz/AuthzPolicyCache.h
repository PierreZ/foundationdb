/*
 * AuthzPolicyCache.h
 *
 * Per-identity key-range authorization policy cache (POC).
 * See src/design/key-range-authz.md.
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include "fdbclient/FDBTypes.h"
#include "fdbclient/NativeAPI.actor.h"
#include "flow/Arena.h"
#include "flow/flow.h"

namespace authz {

enum class Perm : uint8_t {
	Denied = 0,
	R = 1,
	W = 2,
};

struct Grant {
	Key begin;
	Key end;
	Perm perm;
};

// System-keys subspace where the policy and admin entries live.
// The cache subscribes to <prefix>/version and re-reads <prefix>/policy/* + <prefix>/admin/*
// when the version changes. Test code writes these keys directly (POC: no special-keys validator).
extern const KeyRangeRef authzKeys;       // [\xff/authz/, \xff/authz0)
extern const KeyRef authzVersionKey;      // \xff/authz/version
extern const KeyRangeRef authzPolicyKeys; // [\xff/authz/policy/, \xff/authz/policy0)
extern const KeyRangeRef authzAdminKeys;  // [\xff/authz/admin/, \xff/authz/admin0)

// Encode/decode a policy value (list of grants) for a single identity.
// Format: uint32 numGrants || numGrants * (uint32 beginLen || begin || uint32 endLen || end || uint8 perm)
Value encodePolicyValue(std::vector<Grant> const& grants);
std::vector<Grant> decodePolicyValue(ValueRef const& v);

class AuthzPolicyCache : public ReferenceCounted<AuthzPolicyCache> {
public:
	AuthzPolicyCache();

	// Background actor: poll authzVersionKey; refresh on change. Fail-closed past staleness limit.
	Future<Void> run(Database cx);

	// Point check: is `identity` (with trust bit `isTrustedPeer`) allowed to perform `op` on `key`?
	bool check(bool isTrustedPeer, std::string const& identity, KeyRef key, Perm op) const;

	// Range check: is `identity` allowed to perform `op` over the entire range `[begin, end)`?
	// Mixed-permission ranges yield false. The caller surfaces a generic permission_denied
	// so the boundary key is not revealed.
	bool checkRange(bool isTrustedPeer, std::string const& identity, KeyRef begin, KeyRef end, Perm op) const;

	bool isFresh() const;

	// Refresh internals — public for use by the background refresh coroutine.
	void rebuildFromSnapshot(RangeResult const& policyRows, RangeResult const& adminRows);
	void markRefreshed(Standalone<StringRef> version);

private:
	bool isAdmin(std::string const& identity) const;
	bool checkAgainstGrants(std::vector<Grant> const& grants, KeyRef begin, KeyRef end, Perm op) const;

	std::map<std::string, std::vector<Grant>> policy;
	std::set<std::string> admins;
	Standalone<StringRef> snapshotVersion; // last seen value of authzVersionKey
	double lastRefresh;                    // monotonic timestamp of most recent successful refresh
	bool everRefreshed;                    // false until the first successful refresh
};

} // namespace authz
