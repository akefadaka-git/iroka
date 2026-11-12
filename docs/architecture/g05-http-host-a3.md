# G05 ingress HTTP host — A3 implementation

## Request boundary

`G05HttpHost` is a bounded HTTP/1.1 host adapter for the existing G05 ingress service. It binds only to a loopback address and is intended to run behind a trusted TLS-terminating reverse proxy.

For POST execution requests it requires:

- An allowlisted Host header.
- `X-Forwarded-Proto: https` from the local reverse-proxy boundary.
- `Content-Type: application/json`.
- A single bounded Content-Length; transfer encoding and duplicate headers are rejected.
- CRLF framing, bounded request/header sizes and a bounded worker queue.
- G01 credential authentication, canonical G02 tenant authority and G09 policy/scope checks.
- A second G09 execution revalidation immediately before calling the operation executor.

The host exposes only `POST /v1/g05/execute` and `GET /healthz`. Responses use `Cache-Control: no-store`, `Connection: close` and `X-Content-Type-Options: nosniff`.

## Deployment assumptions

The host deliberately does not terminate TLS itself. Production deployment must provide a local reverse proxy that:

- Listens on the public TLS interface and uses current TLS configuration.
- Proxies only to the loopback host address.
- Rewrites/sets the Host and `X-Forwarded-Proto` headers itself.
- Prevents untrusted local network access to the host port.
- Applies request-rate and connection limits at the edge.

The application host does not trust arbitrary forwarded client-IP headers.

## Remaining operational integration

This increment is a reusable host adapter, not yet a production executable. A concrete G05 operation executor, binary/service entrypoint, proxy configuration, secret loading, graceful shutdown, service supervision, monitoring, production Host allowlist and live operational rehearsal remain required. No production service is listening as a result of this change.
