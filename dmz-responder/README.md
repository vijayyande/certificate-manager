# cm-dmz-responder

A stateless **CRL and OCSP responder** designed to run in a **demilitarized zone (DMZ)** in front of the
`certificate-manager` (CM) application. It answers CRL distribution-point and OCSP requests from external
clients by proxying the protocol requests to the internal CM over REST and caching the signed bytes it
returns.

This is a Maven module of the `certificate-manager` reactor: `D:\Projects\temp\CM\dmz-responder`.
Build it from the project root (`mvn ... -pl dmz-responder`) or together with CM (`mvn ...` builds both).

```
External clients ──► DMZ ──► cm-dmz-responder ──(REST, internal network)──► certificate-manager (internal)
 (CRL + OCSP)          ├── TLS terminated by edge proxy            ▲
                       │                                           │ signs CRLs + OCSP responses
                       └── holds NO CA keys, NO database           │ with the CA keys (kept inside CM)
```

Because the DMZ responder **never holds a CA private key and never signs anything**, compromise of the DMZ
host does not expose any signing material. It only forwards protocol requests and relays the signed bytes
that CM produces.

## Endpoints

The responder mirrors CM's public responder paths, so certificates issued with the DMZ host name in their
CRL distribution point / OCSP AIA extensions resolve here unchanged.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/crl/{caRef}` | Current CRL (DER, `application/pkix-crl`). `caRef` = backend CA id, CA serial hex (the form embedded in issued certs), or CA name. |
| `POST` | `/api/ocsp` | OCSP request (DER, `application/ocsp-request`) → signed response (`application/ocsp-response`). |
| `GET` | `/api/ocsp?request=<base64url>` | RFC 5019 OCSP GET (also accepts `base64=`). |
| `GET` | `/health` | Liveness + cache sizes for the load balancer. |

## How it works

1. **CRL** — resolves `{caRef}` to the backend CA id via a cached `GET /api/ca/active` (name/serial → id),
   then fetches `GET /api/crl/{caId}` from CM.
2. **OCSP** — forwards the raw DER request to CM's `POST /api/ocsp`. The response is produced and *signed by
   CM* with the issuer CA key; the DMZ just relays it.
3. **Validation** — every response from CM is structurally validated (BC `X509CRLHolder` / `OCSPResp`) before
   it is cached, so garbage can never be served to clients.
4. **Caching** — signed bytes are cached per key (CRL by CA id, OCSP by SHA-256 of the request, CA list
   once). Concurrent refreshes of the same key are deduplicated. If CM is unreachable, the last cached
   (even expired) entry is served instead of failing (`cm.serve-stale-on-error`).
5. **Hardening** — request size cap for OCSP, strict security headers, and the app has no database, no
   secrets beyond the CM service-account password (via env var), and no outbound traffic other than the
   configured `cm.base-url`.

## Configuration

All settings live in `application.yml` and are overridable through environment variables:

| Property | Env var | Default |
|---|---|---|
| `cm.base-url` | `CM_BASE_URL` | `http://localhost:8443` |
| `cm.username` | `CM_RESPONDER_USER` | `responder` |
| `cm.password` | `CM_RESPONDER_PASSWORD` | *(none)* |
| `cm.crl-cache-seconds` | `CM_CRL_CACHE_SECONDS` | `300` |
| `cm.ocsp-cache-seconds` | `CM_OCSP_CACHE_SECONDS` | `60` |
| `cm.ca-list-cache-seconds` | `CM_CA_LIST_CACHE_SECONDS` | `300` |
| `cm.max-ocsp-request-bytes` | `CM_MAX_OCSP_BYTES` | `16384` |
| `cm.connect-timeout-ms` | `CM_CONNECT_TIMEOUT_MS` | `5000` |
| `cm.read-timeout-ms` | `CM_READ_TIMEOUT_MS` | `10000` |
| `cm.serve-stale-on-error` | `CM_SERVE_STALE` | `true` |

## Deploying to the DMZ

1. **Create the service account in CM** (least privilege). In the CM admin UI → *Users* → *New user*,
   create `responder` with a strong password and the `REQUESTER` role (enough to read the active CA list;
   the CRL and OCSP endpoints on CM are public).
2. **Build** (from the `certificate-manager` root): `mvn -q -pl dmz-responder -DskipTests package` →
   `dmz-responder/target/cm-dmz-responder-0.0.1-SNAPSHOT.jar`.
3. **Run**: `java -jar cm-dmz-responder-0.0.1-SNAPSHOT.jar` with
   `CM_BASE_URL=http://<internal-cm-host>:8443`, `CM_RESPONDER_PASSWORD=...` and a non-default port if needed.
4. **Firewall** (DMZ zone):
   - inbound: only the responder port from clients (terminate TLS at the edge reverse proxy);
   - outbound: only the internal CM host:port (egress whitelist); nothing else.
5. **Certificates** issued for external consumption should carry the DMZ responder's host name in their
   CRL distribution point (`cm.crl.url-base`) and OCSP AIA (`cm.ocsp-url`) so clients reach the DMZ, not CM.

## Tests

```
mvn -pl dmz-responder test          # from the certificate-manager root
mvn test                            # whole reactor: certificate-manager + dmz-responder
```

- `ResponderIntegrationTest` — OCSP POST/GET forwarding, base64url decoding, caching (identical requests hit
  the backend once), CRL id/serial/name resolution, 400/404 handling, security headers (CM client mocked).
- `ResponderServeStaleIntegrationTest` — stale-serving when CM is down, 503 when nothing is cached, 404 pass-through.
- `CmClientValidationTest` — structural validation of CRL/OCSP bytes coming from CM.
- `OcspLiveProbe` — skipped by default; true end-to-end check against a live CM + responder:

```
mvn -pl dmz-responder test -Dtest=OcspLiveProbe -Ddmz.baseUrl=http://localhost:8080 \
         -Dcm.baseUrl=http://localhost:8089 -Dcm.user=admin -Dcm.password=admin123
```

The probe issues a certificate through CM, builds a real OCSP request, checks the DMZ's POST *and* GET
responses are successful and signed, and asserts the DMZ CRL bytes equal CM's.
