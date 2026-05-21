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
	// Verified mTLS peer identity for this request, captured server-side at deserialization
	// (the default constructor fires inside receiver->receive() while the thread-local is set).
	// Empty on the client side. Used by the per-identity key-range authz check in CommitProxy / SS.
	// See src/design/key-range-authz.md.
	std::string _peerIdentity;
	// Whether the connection delivering this request is a trusted (cluster-internal) peer.
	// Captured at deserialization for the same reason as _peerIdentity — the originating
	// thread-local is reset before the handler actor resumes.
	bool _isTrustedPeer;

public:
	double requestTime() const {
		ASSERT(_requestTime > 0.0);
		return _requestTime;
	}

	void setRequestTime(double requestTime) { _requestTime = requestTime; }

	std::string const& peerIdentity() const { return _peerIdentity; }
	void setPeerIdentity(std::string identity) { _peerIdentity = std::move(identity); }

	bool isTrustedPeer() const { return _isTrustedPeer; }
	void setIsTrustedPeer(bool trusted) { _isTrustedPeer = trusted; }

	TimedRequest() : _isTrustedPeer(false) {
		if (!FlowTransport::isClient()) {
			_requestTime = g_network->timer();
			_peerIdentity = FlowTransport::transport().currentDeliveryPeerIdentity();
			_isTrustedPeer = FlowTransport::transport().currentDeliveryPeerIsTrusted();
		} else {
			_requestTime = 0.0;
		}
	}
};

#endif
