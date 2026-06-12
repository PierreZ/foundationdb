/*
 * ApplyMetadataMutation.h
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2026 Apple Inc. and the FoundationDB project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FDBSERVER_APPLYMETADATAMUTATION_H
#define FDBSERVER_APPLYMETADATAMUTATION_H
#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

#include "fdbclient/AuthzPolicy.h"
#include "fdbclient/BackupAgent.h"
#include "fdbclient/MutationList.h"
#include "fdbclient/Notified.h"
#include "fdbclient/StorageServerInterface.h"
#include "fdbclient/SystemData.h"
#include "fdbserver/kvstore/IKeyValueStore.h"
#include "fdbserver/core/LogProtocolMessage.h"
#include "fdbserver/logsystem/LogSystemConsumer.h"
#include "flow/FastRef.h"

class AccumulativeChecksumBuilder;

// applyMetadataMutations() is shared with resolver/clustercontroller code, so
// it depends on a narrow commit-proxy view instead of the full ProxyCommitData
// definition from the commitproxy module.
struct ApplyMetadataRangeLock {
	virtual ~ApplyMetadataRangeLock() = default;
	virtual bool pendingRequest() const = 0;
	virtual void setPendingRequest(const Key& startKey, const RangeLockStateSet& lockSetState) = 0;
	virtual void consumePendingRequest(const Key& endKey) = 0;
};

struct ApplyMutationsData {
	Future<Void> worker;
	Version endVersion;
	Reference<KeyRangeMap<Version>> keyVersion;
};

struct ApplyMetadataProxyContext {
	UID dbgid;
	IKeyValueStore* txnStateStore = nullptr;
	KeyRangeMap<std::set<Key>>* vecBackupKeys = nullptr;
	KeyRangeMap<ServerCacheInfo>* keyInfo = nullptr;
	std::map<Key, ApplyMutationsData>* uid_applyMutationsData = nullptr;
	PublicRequestStream<CommitTransactionRequest> commit;
	Database cx;
	NotifiedVersion* committedVersion = nullptr;
	std::map<UID, Reference<StorageInfo>>* storageCache = nullptr;
	std::map<Tag, Version>* tag_popped = nullptr;
	std::unordered_map<UID, StorageServerInterface>* tssMapping = nullptr;
	// Per-identity key-range authz policy map maintained on this proxy (POC; key-range-authz-v1.md).
	// Updated in version order from \xff/authz/policy/* metadata mutations; read for write-side
	// enforcement in CommitProxyServer.
	std::map<std::string, authz::PolicyEntry>* authzPolicyMap = nullptr;
	uint16_t commitProxyIndex = 0;
	std::shared_ptr<AccumulativeChecksumBuilder> acsBuilder = nullptr;
	Optional<LogEpoch> epoch;
	ApplyMetadataRangeLock* rangeLock = nullptr;
};

// Resolver's data for applyMetadataMutations() calls.
struct ResolverData {
	const UID dbgid;
	IKeyValueStore* txnStateStore = nullptr;
	KeyRangeMap<ServerCacheInfo>* keyInfo = nullptr;
	Arena arena;
	// Whether configuration changes. If so, a recovery is forced.
	bool& confChanges;
	bool initialCommit = false;
	Reference<LogSystemConsumer> logSystemConsumer = Reference<LogSystemConsumer>();
	LogPushData* toCommit = nullptr;
	Version popVersion = 0; // exclusive, usually set to commitVersion + 1
	std::map<UID, Reference<StorageInfo>>* storageCache = nullptr;
	std::unordered_map<UID, StorageServerInterface>* tssMapping = nullptr;
	// Per-identity key-range authz policy map maintained on this resolver (POC; key-range-authz-v2.md).
	// Needed so the resolver makes the same identity-cap drop decision as every commit proxy.
	std::map<std::string, authz::PolicyEntry>* authzPolicyMap = nullptr;

	// For initial broadcast
	ResolverData(UID debugId,
	             IKeyValueStore* store,
	             KeyRangeMap<ServerCacheInfo>* info,
	             bool& forceRecovery,
	             std::map<std::string, authz::PolicyEntry>* authzPolicyMap = nullptr)
	  : dbgid(debugId), txnStateStore(store), keyInfo(info), confChanges(forceRecovery), initialCommit(true),
	    authzPolicyMap(authzPolicyMap) {}

	// For transaction batches that contain metadata mutations
	ResolverData(UID debugId,
	             Reference<LogSystemConsumer> logSystemConsumer,
	             IKeyValueStore* store,
	             KeyRangeMap<ServerCacheInfo>* info,
	             LogPushData* toCommit,
	             bool& forceRecovery,
	             Version popVersion,
	             std::map<UID, Reference<StorageInfo>>* storageCache,
	             std::unordered_map<UID, StorageServerInterface>* tssMapping,
	             std::map<std::string, authz::PolicyEntry>* authzPolicyMap = nullptr)
	  : dbgid(debugId), txnStateStore(store), keyInfo(info), confChanges(forceRecovery),
	    logSystemConsumer(logSystemConsumer), toCommit(toCommit), popVersion(popVersion), storageCache(storageCache),
	    tssMapping(tssMapping), authzPolicyMap(authzPolicyMap) {}
};

inline bool isMetadataMutation(MutationRef const& m) {
	// FIXME: This is conservative - not everything in system keyspace is necessarily processed by
	// applyMetadataMutations
	if (m.type == MutationRef::SetValue) {
		return (m.param1.size() && m.param1[0] == systemKeys.begin[0] &&
		        !m.param1.startsWith(nonMetadataSystemKeys.begin));
	} else if (m.type == MutationRef::ClearRange) {
		return m.param2.size() > 1 && m.param2[0] == systemKeys.begin[0] &&
		       !nonMetadataSystemKeys.contains(KeyRangeRef(m.param1, m.param2));
	} else {
		return false;
	}
}

Reference<StorageInfo> getStorageInfo(UID id,
                                      std::map<UID, Reference<StorageInfo>>* storageCache,
                                      IKeyValueStore* txnStateStore);

// Per-identity key-range authz (POC; key-range-authz-v2.md): would applying this transaction's
// \xff/authz/policy/ sets push the number of distinct identities past maxIdentities? The SAME rule
// must be evaluated by the commit proxy that owns the batch (to reject the txn with
// authz_too_many_identities) and by every metadata applier (other proxies via the resolver's
// forwarded state transactions, the resolver itself) so all txnStateStores make identical
// accept/drop decisions in version order. On accept, the txn's new identities are merged into
// batchNewIdentities (the proxy pre-pass scans a whole batch against a not-yet-updated map; pass a
// fresh set per txn when the map advances between calls).
bool authzTxnExceedsIdentityCap(const std::map<std::string, authz::PolicyEntry>& policyMap,
                                const VectorRef<MutationRef>& mutations,
                                int maxIdentities,
                                std::set<std::string>& batchNewIdentities);

void applyMetadataMutations(SpanContext const& spanContext,
                            const ApplyMetadataProxyContext& proxyMetadata,
                            Arena& arena,
                            Reference<LogSystemConsumer> logSystemConsumer,
                            const VectorRef<MutationRef>& mutations,
                            LogPushData* pToCommit,
                            bool& confChange,
                            Version version,
                            Version popVersion,
                            bool initialCommit,
                            bool provisionalCommitProxy);

void applyMetadataMutations(SpanContext const& spanContext,
                            const UID& dbgid,
                            Arena& arena,
                            const VectorRef<MutationRef>& mutations,
                            IKeyValueStore* txnStateStore);

bool containsMetadataMutation(const VectorRef<MutationRef>& mutations);

// Resolver's version

void applyMetadataMutations(SpanContext const& spanContext,
                            ResolverData& resolverData,
                            const VectorRef<MutationRef>& mutations);

#endif
