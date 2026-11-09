# CIW A3 HTTP runtime composition

Status: implementation contract for the A3 answer-only slice. This document does not authorize production activation, merge, or deployment.

## Trust and session composition

The HTTP transport accepts only these host-only cookies:

- `__Host-iroka_credential`: compact Ed25519 JWS credential, HttpOnly, Secure, Path=/, SameSite=Strict.
- `__Host-iroka_session`: opaque session ID minted by the trusted session issuer, with the same cookie attributes.

The trusted SSO/session issuer must:

1. Verify the credential through the G01 `Ed25519CredentialVerifier`.
2. Resolve the subject's one active tenant from the authoritative membership directory.
3. Mint a cryptographically random session ID.
4. Call `SqliteSessionRegistry::register_verified` with the verified principal, session ID, tenant, issued-at and expiry.
5. Set both cookies. The application credential cookie must not be made available to JavaScript.

The credential payload includes `rv`, the issuer-wide revocation epoch. The G01 verifier rejects credentials whose epoch differs from the durable revocation registry. Every newly applied credential or signing-key revocation increments that issuer's epoch; credentials from the previous epoch must be reissued. Application sessions are bound to the verified signing key, credential ID, revocation epoch, and credential validity interval. The session adapter rechecks these values during every generated chunk and fails closed if the revocation store is unavailable.

Use the same shared `Arc<SqliteSecurityStore>` for the G01 verifier and `SqliteSessionRegistry::open_with_kernel_store`. Do not substitute `NoRevocations` or development bypass features in production builds.

## HTTP server

Construct the service with trusted instances of:

- the authoritative `SqliteTenantDirectory` (membership updates are performed only by a trusted synchronization process, never by an HTTP request);
- the G01-bound `SqliteSessionRegistry`;
- `KernelConversationAuthorizer` using Arc-owned verified policy, verified genesis, Owner approval verifier, and append-only audit sink;
- the conversation SQLite store, signed-policy budget limits, retention policy, and the synthetic A3 answer generator.

Pass the service and `G01CookieAuthenticator` to `HttpServer::new`, bind the listener to loopback, and call `serve`. The HTTP adapter is intentionally not a TLS terminator. Place it behind a trusted TLS reverse proxy; do not expose the raw listener to the public network. The proxy must preserve the original Host header and must not permit untrusted clients to inject trusted forwarding headers.

The server enforces same-origin POSTs by matching the Origin authority exactly to Host, rejects duplicate security headers/cookies and transfer-encoding, caps headers and JSON bodies, limits active HTTP connections and retained generation states, and emits no-store responses. Browser requests use same-origin credentials and receive live generation events through SSE.

## A3 endpoint contract

- `GET /api/v1/conversations`
- `POST /api/v1/conversations` with `client_request_id` and `locale`
- `GET /api/v1/conversations/{conversation_id}/messages`
- `POST /api/v1/conversations/{conversation_id}/turns` with `Idempotency-Key`, `input.text`, and `locale`
- `GET /api/v1/generations/{assistant_turn_id}/events?conversation_id={conversation_id}`
- `POST /api/v1/conversations/{conversation_id}/turns/{assistant_turn_id}/cancel`

The transport persists partial assistant output before publishing each delta. A cancellation request signals the active generation token; the worker records the terminal cancelled state. The SSE event history is bounded in memory and can be replayed for a completed turn from the conversation store after a process restart.

## Explicit A3 boundary

This is a library/runtime integration contract, not a standalone service binary or a production SSO issuer. The credential/session issuer, membership synchronization source, TLS proxy, durable shared database for multi-node deployment, and external live operator configuration must be supplied by the trusted host application. The A3 generator remains synthetic-only; no production model/provider is enabled. A4 must verify the host application's real cookie issuance, tenant isolation, key/credential revocation, streaming, cancellation races, and restart/replay behavior before any production-readiness claim.
