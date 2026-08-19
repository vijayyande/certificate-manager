# Certificate Manager

A complete digital certificate management platform built with Spring Boot 3. It provides:

- **CA management** — generate root/intermediate CAs (RSA or EC) issued immediately on request
- **PKCS#11 / HSM support** — connect a hardware token (SoftHSM2, smart card, HSM) and keep CA private keys on the device; all signing (CAs, leaf certs, CRLs, OCSP) happens natively on the token
- **Certificate issuance from CSR** — upload a PKCS#10 CSR, get a signed X.509 certificate immediately
- **Lifecycle management** — revoke, suspend, and resume certificates; revoke/suspend CAs
- **CRL support** — automatic CRL generation on every revocation, RFC 5280 compliant, served in DER and PEM, with history kept per CA
- **OCSP responder** — RFC 6960 compliant binary responder plus a simple HTTP status-check endpoint
- **Management UI** — single-page web console (no build tooling required) covering all of the above
- **Role-based access** — `REQUESTER`, `ADMIN` with HTTP Basic authentication

## Tech stack

| Component | Choice |
|---|---|
| Framework | Spring Boot 3.3 (Java 21) |
| Crypto | Bouncy Castle 1.78 (`bcprov-jdk18on`, `bcpkix-jdk18on`) |
| Persistence | Spring Data JPA + H2 (file-based by default; swap for any JDBC DB) |
| Security | Spring Security, HTTP Basic, in-memory users |

## Build & run

Requires **JDK 21** and **Maven 3.9+**.

```bash
mvn clean package                          # builds certificate-manager + the dmz-responder module
java -jar certificate-manager/target/certificate-manager-0.0.1-SNAPSHOT.jar
```

Then open <http://localhost:8443>.

### Modules

The project is a Maven reactor (`certificate-manager-parent`) with two application modules:

| Module | Purpose | Location |
|---|---|---|
| `certificate-manager` | this application | [`certificate-manager/`](certificate-manager/) |
| `dmz-responder` | DMZ-hosted CRL/OCSP responder that proxies to this app over REST | [`dmz-responder/`](dmz-responder/README.md) |

Build only the responder with `mvn -pl dmz-responder package`; run its tests with `mvn -pl dmz-responder test`.

> The first start **bootstraps a demo root CA and intermediate CA** (`CN=Demo Root CA`, `CN=Demo Intermediate CA`) so the platform is usable immediately. CAs and certificates requested through the API are **issued immediately** — there is no approval queue.
>
> Data is stored in `./data/cmdb.mv.db`. The H2 console is at `/h2-console`.

## Demo accounts

Accounts are seeded into the database on first startup and can be managed by any admin from the **Users** tab.

| User | Password | Roles |
|---|---|---|
| `admin` | `admin123` | ADMIN, REQUESTER |
| `requester` | `requester123` | REQUESTER |

## Immediate issuance

- Every CA request and every CSR / manual certificate submission is **issued immediately** by the platform — no approval queue, no pending state.
- A failed request (e.g. invalid parameters, disabled PKCS#11 device) is rejected synchronously with **400** and nothing is stored.
- CAs and certificates record the initiator in the `requestedBy` field (`approverName` column retained for compatibility).

## REST API summary

### CAs
CA management is **admin only**. The one exception is `GET /api/ca/active`, which any authenticated user can read (it powers the CSR issuer and CRL dropdowns).

A CA request can choose its **key storage** (`keyStorage`): `DATABASE` (default — private key PEM kept in the platform DB) or `PKCS11` (private key generated on, and never leaving, the configured PKCS#11 device; only the certificate is stored in the DB). When `keyStorage` is omitted, the platform default from `Settings > PKCS#11 device` is used. PKCS#11 storage is validated at request time (device must be enabled with a library path) and the device signs the CA's certificates, CRLs and OCSP responses natively.

| Method & path | Access | Description |
|---|---|---|
| `POST /api/ca` | admin | Create and activate a new CA immediately |
| `GET /api/ca` | admin | List all CAs |
| `GET /api/ca/active` | any authenticated user | List active CAs (issuer selection) |
| `GET /api/ca/{id}` | admin | CA details, including `keyAlgorithm`, `keySize` and `signatureAlgorithm` |
| `GET /api/ca/{id}/certificate.pem` | admin | Download CA certificate (PEM) |
| `POST /api/ca/{id}/revoke` | admin | Revoke a CA |
| `POST /api/ca/{id}/suspend` | admin | Suspend a CA |
| `POST /api/ca/{id}/resume` | admin | Resume a CA |

### Certificates
| Method & path | Access | Description |
|---|---|---|
| `POST /api/certificates/csr` | any authenticated role | Submit a PKCS#10 CSR for signing (issued immediately) |
| `POST /api/certificates/request` | any authenticated role | Request a certificate from manual fields; the platform generates the key pair and the request internally. Optional `profileId` (non-CA profile — its `keyStorage` decides where the key lives), `additionalExtensions` (custom OIDs), and `validityMinutes` (1..525600) for sub-day validity. `keyAlgorithm`/`keySize` select the key (see *Key algorithms & sizes*) |
| `GET /api/certificates` | any authenticated role | List/search certificates & requests. All filters optional and combinable: `?q=` (case-insensitive substring on common name, subject DN, serial number, requester), `?status=` (PENDING/ISSUED/SUSPENDED/REVOKED), `?caId=`. No owner scoping: admins **and** requesters can search and view every certificate. Newest first |
| `GET /api/certificates/{id}` | any authenticated role | Certificate/request details, including `keyAlgorithm`, `keySize` and (once issued) `signatureAlgorithm` |
| `GET /api/certificates/{id}/pem` | any authenticated role | Download certificate (PEM) |
| `GET /api/certificates/{id}/key` | requester/owner only | Download the private key PEM generated for a manual request (no one else, not even admin) |
| `POST /api/certificates/{id}/revoke` | admin | Revoke (`{"reason":"KEY_COMPROMISE"}`) |
| `POST /api/certificates/{id}/suspend` | admin | Suspend (certificateHold) |
| `POST /api/certificates/{id}/resume` | admin | Resume |

### Profiles
Certificate profiles bundle key algorithm, key size, validity, key usage, extended key usage, custom extensions and **key storage**. Ten defaults are seeded at startup (CA, SSL, Client, Code Signing, Email, Document Signing, Class 1/2/3, Aadhaar eSign). Anyone can read profiles; only **admin** creates/updates/deletes them. A requester selects a profile when requesting a certificate — CA profiles are rejected for non-admins.

**Key storage (`keyStorage`, optional, defaults to `DATABASE`).** A profile can choose where the platform-generated key pair is stored: `DATABASE` keeps the private key PEM in the platform DB (the owner can download it from the Certificates tab) or `PKCS11` keeps it on the configured PKCS#11 device. With `PKCS11`, the private key is generated **on the device at issuance time** — the request record only carries the CSR intent — and the issued certificate is written next to it under a unique token alias (`cert-<cn>-<random>`). The token key is never exportable, so no "Key" download is offered for such certificates and `GET /api/certificates/{id}/key` answers **400**. Requests using a `PKCS11` profile are rejected with **400** while the device is disabled or the library is not configured in `Settings > PKCS#11 device`; the profile itself can be created at any time.

| Method & path | Access | Description |
|---|---|---|
| `GET /api/profiles/types` | any authenticated role | List the built-in profile types with their default parameters |
| `GET /api/profiles` | any authenticated role | List all profiles |
| `GET /api/profiles/{id}` | any authenticated role | Profile details |
| `POST /api/profiles` | admin | Create a profile |
| `PUT /api/profiles/{id}` | admin | Update a profile |
| `DELETE /api/profiles/{id}` | admin | Delete a profile |

**Built-in profile types.** Each type carries sensible defaults (key algorithm, size, validity, key usage, extended key usage) so a profile can be created from just a name + type; every field still overrides when sent:

| Type | Defaults (algorithm / size / validity) | Key usage | Extended usage |
|---|---|---|---|
| `CUSTOM` | administrator-defined | — | — |
| `CA` | RSA 3072 / 3650 days, CA:TRUE | keyCertSign, cRLSign | — |
| `SERVER` | RSA 2048 / 825 days | digitalSignature, keyEncipherment | serverAuth |
| `CLIENT` | RSA 2048 / 365 days | digitalSignature | clientAuth |
| `CODE_SIGNING` | RSA 2048 / 365 days | digitalSignature, nonRepudiation | codeSigning |
| `EMAIL` | RSA 2048 / 365 days | digitalSignature, keyEncipherment | emailProtection |
| `DOCUMENT_SIGNING` | RSA 2048 / 365 days | digitalSignature, nonRepudiation | emailProtection |
| `CLASS_1` | RSA 2048 / 365 days | digitalSignature, keyEncipherment | clientAuth, emailProtection |
| `CLASS_2` | RSA 2048 / 365 days | digitalSignature, nonRepudiation, keyEncipherment | clientAuth, emailProtection |
| `CLASS_3` | RSA 3072 / 730 days | digitalSignature, nonRepudiation, keyEncipherment, keyAgreement | serverAuth, clientAuth, codeSigning, emailProtection |
| `AADHAAR_ESIGN` | RSA 2048 / 365 days | digitalSignature, nonRepudiation | emailProtection |

Example — create a code-signing profile with only the type (defaults applied server-side):

```bash
curl -u admin:admin123 -H "Content-Type: application/json" -X POST http://localhost:8443/api/profiles \
  -d '{"name":"Code Signing","type":"CODE_SIGNING"}'
```

`additionalExtensions` entries are `{"oid":"1.2.3.4","type":"STRING|INTEGER|BOOLEAN|OCTETS","value":"..."}`. On issuance the profile's key usage, extended key usage and custom extensions (merged with any request-level extensions) are embedded in the X.509 certificate.

Validity is expressed in **days** (`validityDays`, 1..3650) or, for sub-day periods down to **1 minute**, in **minutes** (`validityMinutes`, 1..525600). `validityMinutes` takes precedence when both are sent. Profiles store the same choice, and a request inherits the profile's validity unless the request overrides it.

### CRL
| Method & path | Description |
|---|---|
| `POST /api/crl/{caId}/generate` | Generate a fresh CRL for the CA |
| `GET /api/crl/{caId}` | Download CRL in DER (`application/pkix-crl`) |
| `GET /api/crl/{caId}/pem` | Download CRL in PEM |
| `GET /api/crl/{caId}/history` | CRL history (last 10 kept) |

CRLs are regenerated automatically whenever a certificate is revoked/suspended/resumed, and nightly at 02:00 (`cm.crl.refresh-cron`). Issued certificates carry the CRL Distribution Point and OCSP AIA extensions.

### OCSP
| Method & path | Description |
|---|---|
| `POST /api/ocsp` | RFC 6960 binary OCSP request → `application/ocsp-response` (public) |
| `GET /api/ocsp/status/{serialHex}` | Human-readable status for a serial (public) |
| `GET /api/ocsp/status?serial=` | Same as above |

### System
| Method & path | Description |
|---|---|
| `GET /api/info` | Platform summary: counts and configuration |
| `GET /api/me` | Current user and roles |

### Users (admin only)
Accounts are persisted in the database (BCrypt-hashed passwords). Admins can create users, **grant/revoke the administrator role** (making another user an admin), enable/disable accounts, reset passwords and delete users from the **Users** tab or the API. Guards: nobody can disable or delete their own account, and the last administrator can never be demoted, disabled or deleted. Every change is written to the signed audit log.

| Method & path | Description |
|---|---|
| `GET /api/users` | List all users (username, roles, enabled, created) |
| `POST /api/users` | Create a user: `{"username":"alice","password":"alice123","admin":false}` |
| `PUT /api/users/{id}` | Update: `{"admin":true|false}` and/or `{"enabled":true|false}` |
| `PUT /api/users/{id}/password` | Reset password: `{"password":"newpass456"}` |
| `DELETE /api/users/{id}` | Delete a user |

### Signed audit log (admin only)
Every significant action (CA create/revoke/suspend/resume, certificate issue/revoke/suspend/resume, CRL generation, OCSP responses, profile create/update/delete, PKCS#11 setting changes, failed logins, rejected API calls, seed data) is recorded in a tamper-evident chain:

- Each entry stores a payload `timestamp|actor|category|action|detail|prevHash`.
- `hash` is the SHA-256 of that payload; `prevHash` of entry *n* equals the `hash` of entry *n−1* (first entry has `prevHash=""`), so reordering, deletion or any modification is detectable.
- `signature` is the HMAC-SHA256 of the payload using a 256-bit secret generated on first startup and persisted in the `audit_key` table (survives restarts). Only `verify` uses the secret; the API never returns it.
- `GET /api/audit/verify` recomputes the whole chain from the database and reports `{valid, total, verified, failedAt, message}`.

| Method & path | Description |
|---|---|
| `GET /api/audit` | Full signed audit log, oldest first: id, timestamp, actor, category, action, detail, prevHash, hash, signature |
| `GET /api/audit/verify` | Recompute the hash chain and check every HMAC signature |

The UI exposes both under **Audit Log** (admin sidebar tab): the entry table plus a *Verify log integrity* button.


### Crypto (key algorithm discovery & validation)
These endpoints expose the supported key algorithms and let clients validate/derive parameters without hardcoding rules. Accessible to any authenticated user; the UI's algorithm and key-size selects are rendered from the catalog.

| Method & path | Description |
|---|---|
| `GET /api/crypto/algorithms` | Supported algorithms (`RSA`, `EC`, `ED25519`, `ED448`) with their key sizes, NIST curves and derived signature algorithms |
| `GET /api/crypto/oids` | Well-known X.509 extension OIDs (friendly label + suggested value type). The UI offers these in a dropdown when adding custom extensions; arbitrary OIDs can still be typed manually |
| `POST /api/crypto/derive` | Validate an algorithm/size and derive the effective parameters: `{"keyAlgorithm":"EC","keySize":521}` → `{"keyAlgorithm":"EC","keySize":521,"signatureAlgorithm":"SHA512withECDSA"}`. Omit `keySize` to use the platform default; unsupported algorithm/size returns **400** |

Example:

```bash
curl -u requester:requester123 -H "Content-Type: application/json" \
  -X POST http://localhost:8443/api/crypto/derive \
  -d '{"keyAlgorithm":"ECDSA","keySize":2048}'
# -> 400 {"message":"EC curve must be P-256 (256), P-384 (384) or P-521 (521)"}
```

### PKCS#11 device (admin only)
| Method & path | Description |
|---|---|
| `GET /api/pkcs11` | Current PKCS#11 settings (`enabled`, provider, library, slot, default key storage). The token PIN is never returned |
| `GET /api/pkcs11/presets` | Known PKCS#11 providers with their typical library paths per OS (SoftHSM2, OpenSC, YubiKey PIV, Utimaco, Thales Luna, Entrust nShield, eToken) |
| `POST /api/pkcs11` | Save PKCS#11 settings (JSON below) |
| `POST /api/pkcs11/test` | Load the provider and verify the token accepts the PIN + slot |
| `POST /api/pkcs11/disconnect` | Unload the provider |

```json
{
  "enabled": true,
  "providerName": "SunPKCS11-CM",
  "libraryPath": "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
  "slotIndex": 0,
  "tokenPin": "1234",
  "keyStorageDefault": "DATABASE"
}
```

In the **Settings** tab the admin can pick a known provider from the preset dropdown (filled from `GET /api/pkcs11/presets`) to pre-fill the provider name, library path and slot, then adjust every field — including choosing among that provider's alternative library paths. Presets carry the recommended library path for the current server OS first; a preset's values are just starting points and can be freely edited or saved as-is.

The provider is built with the JDK's SunPKCS11 provider (`Provider.configure`, JEP 315). When a CA is issued with `keyStorage: "PKCS11"`, its key pair is generated directly on the token (`CKA_TOKEN`/`CKA_SIGN`), the certificate is written next to it under the CA's token alias (`pkcs11Alias`, defaulting to the CA name), and signing operations resolve the key from the device. Requests for PKCS#11-backed CAs are rejected with **400** when the device is not enabled or the library is not configured; a bad library fails `test` gracefully (400, not a 500).

## Key algorithms & sizes

CAs, certificate profiles and manual certificate requests accept `keyAlgorithm` (`RSA`, `EC`, `ED25519`, `ED448`) and `keySize`:

| Algorithm | `keySize` (bits) | Notes |
|---|---|---|
| `RSA` | `2048`, `3072`, `4096` | Signature `SHA256withRSA`; CAs keep `cm.ca.key-size`/`cm.ca.signature-algorithm` unless overridden |
| `EC` | `256` → P-256, `384` → P-384, `521` → P-521 | `keySize` selects the NIST curve; signature `SHA256withECDSA` (256), `SHA384withECDSA` (≥384), `SHA512withECDSA` (≥521) |
| `ED25519` | fixed `256` | Signature `Ed25519` |
| `ED448` | fixed `456` | Signature `Ed448` |

- The key-size select is **disabled for fixed-size algorithms** (Ed25519/Ed448); for `EC`, `keySize` drives the curve.
- An unsupported algorithm or size is rejected with **400** (e.g. `EC` with `2048`). When omitted, the platform defaults apply (`defaultKeySizeFor` per algorithm; CAs fall back to `cm.ca.key-size`).
- CA signature algorithms for `EC`/EdDSA CAs are derived from the CA key and stored on the CA; the derived algorithm is also used for CRL/OCSP and leaf signing. `ED25519`/`ED448` CAs are stored as PKCS#8 PEMs and re-parsed at signing time.
- EC private keys are stored and downloaded as standard **PKCS#8** (`-----BEGIN PRIVATE KEY-----`); SEC1 `EC PRIVATE KEY` and PKCS#1 `RSA PRIVATE KEY` PEMs are also accepted on parse.
- `PKCS11` key storage generates EC keys on the token using the curve selected by `keySize`; EdDSA on a token falls back gracefully if the device lacks support.
- Clients can discover the supported algorithms/sizes and validate their own values against the same rules via `GET /api/crypto/algorithms` and `POST /api/crypto/derive` (see *Crypto* under the REST API summary).

## Example: submit and sign a CSR

```bash
# create a key + CSR (openssl)
openssl req -new -newkey rsa:2048 -nodes -keyout app.key -out app.csr \
  -subj "/CN=myapp.example.com"

# get the CSR into a JSON payload (jq or paste manually)
CSR=$(ruby -e 'puts File.read("app.csr")')  # or use a text editor

# requester submits; the certificate is issued immediately
curl -u requester:requester123 -H "Content-Type: application/json" -X POST http://localhost:8443/api/certificates/csr \
  -d "{\"csrPem\":\"$CSR\",\"issuerCaId\":2,\"requestedBy\":\"requester\"}"

# download the issued certificate
curl -u requester:requester123 http://localhost:8443/api/certificates/1/pem
```

## Example: manual certificate request (no external CSR)

For the **Request Certificate** page (or `POST /api/certificates/request`), the platform generates the key pair and builds the request internally. The certificate is issued immediately, and the requester downloads the certificate and the private key:

```bash
curl -u requester:requester123 -H "Content-Type: application/json" -X POST http://localhost:8443/api/certificates/request \
  -d '{"commonName":"manual.example.com","organization":"Manual Corp","country":"US",\
       "dnsNames":["manual.example.com"],"ipAddresses":["10.0.0.5"],\
       "keyAlgorithm":"RSA","keySize":2048,"validityDays":365,"issuerCaId":2,"requestedBy":"requester"}'

# download cert + private key (owner or admin)
curl -u requester:requester123 http://localhost:8443/api/certificates/1/pem
curl -u requester:requester123 http://localhost:8443/api/certificates/1/key
```

Subject Alternative Names are carried from the request into the issued certificate. If no SANs are given, the common name is used.

## Configuration

Key properties in `src/main/resources/application.yml`:

| Property | Default | Meaning |
|---|---|---|
| `cm.ca.key-size` | `4096` | CA RSA key size |
| `cm.ca.signature-algorithm` | `SHA256withRSA` | CA signing algorithm |
| `cm.ca.default-validity-days` | `3650` | CA lifetime |
| `cm.cert.default-validity-days` | `365` | Certificate lifetime |
| `cm.crl.validity-days` | `30` | CRL nextUpdate window |
| `cm.crl.url-base` | `http://localhost:8443/api/crl/` | CRL DP extension value |
| `cm.ocsp-url` | `http://localhost:8443/api/ocsp` | OCSP AIA extension value |

## Security notes (production hardening)

- Users are stored in the database with **BCrypt**-hashed passwords. Passwords are never returned by any endpoint, and the reset endpoint replaces the hash (old passwords no longer work).
- Private keys are stored in the DB (PEM) for `DATABASE` key storage. For production, prefer the built-in **PKCS#11** key storage so CA keys are generated on and never leave an HSM / smart card / SoftHSM2 token — or store keys in an encrypted keystore / KMS.
- The OCSP responder is publicly accessible by design (clients must be able to reach it without credentials).
- Serve over TLS (`server.ssl.*`) in production and lock down `/h2-console`.
- The signed audit log secret lives in the `audit_key` table; protect the database accordingly (an attacker who can write to the DB can also rotate the secret, so rely on the log for detection, not absolute proof).
- Role-based UI: **admin** sees everything; **requester** sees Certificates, Request Certificate, CRL, OCSP and the Crypto explorer. Backend access rules enforce these limits regardless of what the UI shows.

## Tests

```bash
mvn test
```

`CertificateManagerIntegrationTest` boots the app and verifies end-to-end: info endpoint, immediate CA creation (no approval queue, admin-only), CSR → immediate signing → revoke → CRL generation → OCSP response round-trip, authorization (requester can issue but not revoke/suspend/generate CRLs; admin can), removed-approval endpoints return 404 (`/api/config`, `/api/approvals`), manual certificate request (fields + SANs + private-key download access control), certificate profiles (seeded defaults, admin CRUD, requester can read but not create, CA profile rejected for requester, profile-driven keyUsage/extendedKeyUsage/custom OID embedded on issuance), built-in profile types (CODE_SIGNING / AADHAAR_ESIGN presets auto-fill defaults and the code-signing EKU lands in the issued certificate), minute-level validity (1-minute cert and profile-driven 90-minute cert), PKCS#11 settings (admin-only access, defaults, PIN never serialized, PKCS#11 CA request rejected with 400 while the device is unavailable, graceful test failure on a bad library, per-request/default key-storage resolution), PKCS#11 provider presets (admin-only, known vendors present, recommended library path always among the known paths, preset values reusable in a settings save), profile key storage (profiles default to DATABASE, a PKCS11-storage profile is creatable while the device is off but a certificate request on it is rejected with 400 until the device is configured, and a DATABASE-backed request still yields a downloadable private key), the extended key algorithms (EC P-384/P-521 profiles and certificates, Ed25519 certificate + PKCS#8 key download, invalid EC size rejected with 400, and an EC P-384 intermediate CA issuing a leaf with SHA384withECDSA), the OID catalog + system-managed/duplicate custom-extension rejection, the signed audit log (admin-only access, hash-chain linkage between consecutive entries, valid end-to-end verification, and tamper detection when a stored field is modified), certificate search & cross-role viewing (both roles find any certificate by common name/serial/requester, filters combine with status, requesters can view certs requested by an admin while the private key stays owner-only), and user management (admin-only, duplicate usernames rejected, created users log in as requester, promotion to administrator grants access to admin endpoints, disabled accounts get 401, password reset invalidates the old password, and self-demotion/self-disable/self-delete are rejected).
