/*
 * X509Identity.h
 *
 * Shared helper for extracting peer identity (common name) from a verified X509 cert.
 * Used by both production (SSLConnection) and simulation (Sim2Conn) — the same parser
 * runs in both, so the production code path is exercised in sim against a real X509
 * minted via flow/MkCert.h. See src/design/key-range-authz.md.
 */

#ifndef FLOW_X509_IDENTITY_H
#define FLOW_X509_IDENTITY_H

#include <string>

// Forward-declare OpenSSL X509 to keep <openssl/x509.h> out of this header.
struct x509_st;
typedef struct x509_st X509;

// Extract the commonName (CN) from the subject of `cert`. Returns empty if cert is null
// or has no CN. Does NOT take ownership of `cert` — caller frees.
std::string extractCommonNameFromX509(X509* cert);

#endif // FLOW_X509_IDENTITY_H
