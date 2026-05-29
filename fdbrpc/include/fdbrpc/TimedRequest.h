/*
 * TimedRequest.h
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

#ifndef FDBRPC_TIMED_REQUEST_H
#define FDBRPC_TIMED_REQUEST_H
#include "flow/network.h"
#pragma once

#include <fdbrpc/fdbrpc.h>

class TimedRequest {
	double _requestTime;
	// Verified mTLS peer identity (cert CN) for this request, captured server-side at
	// deserialization (the default constructor fires inside receiver->receive() while the
	// thread-local is set). Empty on the client side. Consumed by the per-identity key-range
	// authz check in CommitProxy / StorageServer. Not serialized — the wire format is unchanged.
	// See src/design/key-range-authz-v1.md.
	std::string _peerIdentity;

public:
	double requestTime() const {
		ASSERT(_requestTime > 0.0);
		return _requestTime;
	}

	void setRequestTime(double requestTime) { _requestTime = requestTime; }

	std::string const& peerIdentity() const { return _peerIdentity; }
	void setPeerIdentity(std::string identity) { _peerIdentity = std::move(identity); }

	TimedRequest() {
		if (!FlowTransport::isClient()) {
			_requestTime = g_network->timer();
			// On the receiving side of a network message this fires during deserialization with the
			// delivery thread-local set, capturing the verified peer cert CN. For locally-constructed
			// requests (same-process / loopback delivery, which never re-deserialize) the delivery
			// context is empty, so fall back to this process's own identity. See key-range-authz-v1.md.
			_peerIdentity = FlowTransport::transport().currentDeliveryPeerIdentity();
			if (_peerIdentity.empty()) {
				_peerIdentity = FlowTransport::transport().localIdentity();
			}
		} else {
			_requestTime = 0.0;
		}
	}
};

#endif
