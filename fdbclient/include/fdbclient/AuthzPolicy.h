/*
 * AuthzPolicy.h
 *
 * Per-identity key-range authorization policy types (POC).
 * See src/design/key-range-authz-v1.md.
 *
 * A policy is a list of (range, perm) grants keyed by mTLS identity (cert CN). It is stored at
 * \xff/authz/policy/<identity> as an encoded PolicyEntry and distributed to every CommitProxy and
 * StorageServer via the metadata-mutation broadcast (modeled on the deleted tenant map), so the
 * authority map is maintained in version order.
 *
 * Kept deliberately narrow (no heavy includes) to limit recompile blast radius.
 */

#ifndef FDBCLIENT_AUTHZ_POLICY_H
#define FDBCLIENT_AUTHZ_POLICY_H
#pragma once

#include <map>
#include <string>
#include <vector>

#include "fdbclient/FDBTypes.h"
#include "flow/serialize.h"

namespace authz {

// Privilege vocabulary. W implies R (a writer can read); Denied grants nothing.
enum class Perm : uint8_t { Denied = 0, R = 1, W = 2 };

// Does a grant carrying `granted` permit an operation requiring `requested`?
inline bool permCovers(Perm granted, Perm requested) {
	if (granted == Perm::W) {
		return requested == Perm::R || requested == Perm::W;
	}
	if (granted == Perm::R) {
		return requested == Perm::R;
	}
	return false;
}

// A single grant: [begin, end) carries permission `perm`.
struct Grant {
	constexpr static FileIdentifier file_identifier = 11020304;
	Key begin;
	Key end;
	uint8_t perm = static_cast<uint8_t>(Perm::Denied);

	Grant() = default;
	Grant(KeyRef begin, KeyRef end, Perm perm) : begin(begin), end(end), perm(static_cast<uint8_t>(perm)) {}

	Perm permission() const { return static_cast<Perm>(perm); }

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, begin, end, perm);
	}
};

// The full per-identity policy: an unordered list of grants (POC uses a linear scan).
struct PolicyEntry {
	constexpr static FileIdentifier file_identifier = 11020305;
	std::vector<Grant> grants;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, grants);
	}

	Value encode() const { return ObjectWriter::toValue(*this, IncludeVersion()); }
	static PolicyEntry decode(ValueRef const& value) {
		return ObjectReader::fromStringRef<PolicyEntry>(value, IncludeVersion());
	}

	// Does this policy allow `op` over the entire [begin, end)? A single grant must fully cover
	// the range (POC: no stitching across grants). A point check passes end == keyAfter(begin).
	bool allows(KeyRef begin, KeyRef end, Perm op) const {
		for (auto const& g : grants) {
			if (g.begin <= begin && end <= g.end && permCovers(g.permission(), op)) {
				return true;
			}
		}
		return false;
	}
};

// Is `identity` permitted `op` over the entire [begin, end)? `adminCN` (when non-empty) is the
// cluster/admin identity with implicit full access — cluster-internal traffic (fdbserver, backup)
// presents this CN. Empty identity (no client cert) is always denied. The caller gates on the
// AUTHZ_ENFORCEMENT_ENABLED knob before calling. See src/design/key-range-authz-v1.md.
inline bool checkAuthorized(std::map<std::string, PolicyEntry> const& policyMap,
                            std::string const& adminCN,
                            std::string const& identity,
                            KeyRef begin,
                            KeyRef end,
                            Perm op) {
	if (!adminCN.empty() && identity == adminCN) {
		return true;
	}
	if (identity.empty()) {
		return false;
	}
	auto it = policyMap.find(identity);
	if (it == policyMap.end()) {
		return false;
	}
	return it->second.allows(begin, end, op);
}

// Point-key overload: treats the key as the single-key range [key, keyAfter(key)).
inline bool checkAuthorized(std::map<std::string, PolicyEntry> const& policyMap,
                            std::string const& adminCN,
                            std::string const& identity,
                            KeyRef key,
                            Perm op) {
	return checkAuthorized(policyMap, adminCN, identity, key, keyAfter(key), op);
}

} // namespace authz

#endif // FDBCLIENT_AUTHZ_POLICY_H
