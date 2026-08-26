# nhcx-gateway

A small, stateless adapter between your system and India's National Health
Claims Exchange (NHCX). One binary, one JSON config, no database.

It does three things:

| | What | How |
| --- | --- | --- |
| **Send** | Your FHIR bundle → NHCX | Completes the `x-hcx-*` headers, encrypts for the recipient (JWE), posts to NHCX, returns NHCX's answer on the same call. |
| **Deliver** | NHCX callback → your system | Decrypts with your private key, posts the plain bundle to your callback URL, then acknowledges NHCX with the required `202` body. |
| **Certificates** | Who can read what | Fetches and caches counterparties' encryption certificates from the participant registry; creates and registers your own. |

Session tokens are obtained and refreshed on their own. Sandbox and
production are one switch apart.

---

## Quick start

```sh
make build                                  # → ./nhcx-gateway (Go 1.26, no CGO)

export NHCX_CLIENT_ID=…  NHCX_CLIENT_SECRET=…  NHCX_GATEWAY_API_KEY=…
./nhcx-gateway config edit                  # arrow-key form; creates config.json
./nhcx-gateway serve                        # checks the setup, fixes what it can, then listens
```

`serve` verifies your credentials, participant record, encryption
certificate and registered endpoint before it listens, and — in a terminal —
offers to fix whatever fails (generate/upload a certificate, re-register the
endpoint, reopen the editor). Details in [Startup checks](#startup-checks).

---

## How it works

```
 your system                     nhcx-gateway                          NHCX
 ───────────                     ────────────                          ────
 POST /out/v1/preauth/submit ──▶ headers · recipient cert · JWE ──▶ POST …/v1/preauth/submit
 {"recipient": "…", "fhir": …}   ◀── 202 + NHCX body ─────────────  202 Accepted
 ◀── 202 {ok, headers, response}

 POST callback/v1/preauth/on_submit ◀── decrypt with your key ◀── POST /in/v1/preauth/on_submit
 {meta, jwe_headers, fhir}                                          {"payload": "<JWE>"}
 ──▶ 2xx                            ──▶ 202 acceptance body ──────▶
```

Both directions are synchronous. There is no queue: if your callback is
down, NHCX gets an error and redelivers (five attempts, then the correlation
id is dropped) — so **your callback must be idempotent on
`x-hcx-correlation_id`**.

---

## Configuration

`config.json` (create with `config init`, edit by hand or with `config edit`):

```json
{
  "env": "sandbox",
  "listen": "127.0.0.1:8090",
  "publicUrl": "https://hcx.example.com/in",
  "apiKey": "${NHCX_GATEWAY_API_KEY}",
  "participant": {
    "participantId": "1000003463@hcx",
    "clientId": "${NHCX_CLIENT_ID}",
    "clientSecret": "${NHCX_CLIENT_SECRET}",
    "privateKey": "@private_key.pem"
  },
  "callback": { "url": "http://127.0.0.1:8765/nhcx/callback" }
}
```

`${NAME}` reads an environment variable; `@file` reads a file relative to
the config. Unknown keys are rejected. Everything else has a default:

| Key | Default | Meaning |
| --- | --- | --- |
| `env` | `sandbox` | `sandbox` or `production` — selects the NHCX gateway, registry, session endpoint and `X-CM-ID`. |
| `listen` | `127.0.0.1:8090` | HTTP listener. |
| `publicUrl` | — | How NHCX reaches this gateway from outside; proposed as the registry `endpoint_url`. |
| `apiKey` | — | Bearer key your system sends to `/out` and `/token`. **Required in production.** |
| `participant.participantId` | — | Your registry code (`@hcx` added if missing). |
| `participant.clientId` / `clientSecret` | — | ABDM credentials from onboarding. |
| `participant.privateKey` | — | RSA key of your registered certificate: PEM, base64 PEM or `@file`. |
| `callback.url` | — | Where decrypted messages are POSTed. |
| `callback.appendPath` | `true` | Append the NHCX path: `…/callback/v1/preauth/on_submit`. |
| `callback.routes` | `{}` | Per-path overrides, used verbatim: `{"v1/claim/on_submit": "http://claims/hook"}`. |
| `callback.timeoutSeconds` | `20` | Time your backend has to accept a delivery (NHCX wants its 202 within 30 s). |
| `callback.apiKey` | — | Sent to your backend as `Authorization: Bearer`. |
| `ledger.enabled` | `true` | Record every message that crosses the gateway (see [Ledger](#ledger)). |
| `ledger.dir` / `retentionDays` / `storeBodies` | `data/ledger` / `30` / `true` | Where records live; how long day folders are kept (0 = forever); whether bundles are stored or only headers and outcomes. |
| `certificate.validityDays` | `365` | Lifetime of a generated certificate (subject is always your participant id). |
| `certificate.privateKeyFile` / `certificateFile` | `private_key.pem` / `certificate.pem` | Where `cert generate` writes. |
| `urls.nhcx` / `urls.participant` / `urls.sessions` | per `env` | Override any endpoint. |
| `auth.mode` | `sessions` | `sessions` = ABDM HIECM gateway (JSON); `get-session` = participant service `/get/session` (form). NHA's documents disagree — use what your onboarding contact confirms. |
| `auth.tokenTtlSeconds` | `1200` | Assumed lifetime when the token response has no expiry. |
| `certs.cacheHours` | `24` | Counterparty certificate cache. |
| `tls.certFile` / `keyFile` | — | Terminate HTTPS on the listener (or use a reverse proxy). |
| `log.level` / `log.format` | `info` / `json` in production, `text` otherwise | `text` is a readable, coloured format for terminals — one line per message (`▲ OUT` / `▼ IN`, path, counterparty, outcome, HTTP status, latency, correlation id); `json` is for log collectors. Bodies and tokens are never logged. |
| `maxBodyBytes` / `outboundTimeoutSeconds` | 8 MiB / `30` | Request body cap; timeout per ABDM call. |

### Environments

| | Sandbox | Production |
| --- | --- | --- |
| NHCX gateway | `https://apisbx.abdm.gov.in/hcx/v1` | `https://apis.abdm.gov.in/hcx/v1` |
| Participant registry | `https://apisbx.abdm.gov.in/pmjay/sbxhcx/participanthcxservice` | `https://apis.abdm.gov.in/pmjay/hcx/participanthcxservice` |
| Sessions | `https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions` | `https://live.abdm.gov.in/api/hiecm/gateway/v3/sessions` |
| `X-CM-ID` | `sbx` | `abdm` |

Sandbox values are verified; production values follow NHA's documented host
swap — confirm against your production onboarding letter and override under
`urls` if they differ.

### The editor

`nhcx-gateway config edit` is a full-screen form over the same file:
**↑/↓** move · **Enter** edit · **←/→** cycle choices / toggle / step numbers ·
**Backspace** reset to default · **Ctrl+S** save · **q** quit. It validates
as you type (including that the private key file exists and parses), shows
the environment default for every blank endpoint, masks secrets, and writes
`${ENV}` / `@file` references back exactly as typed.

---

## Startup checks

`serve` (and `check`) run these in order:

```
checking setup for 1000003463@hcx (sandbox)…
  ✓ session token            issued by https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions
  ✓ participant record       1000003463@hcx · Healthica · endpoint https://hcx.example.com/in
  ✓ encryption certificate   registry certificate matches participant.privateKey
  ✓ local listener           127.0.0.1:8090 (started for this check)
  ✓ registered endpoint      https://hcx.example.com/in/healthz reaches this gateway (probe acknowledged)
```

| Check | Fails when | In a terminal, the gateway offers to… |
| --- | --- | --- |
| Config | file missing, `clientId`/`clientSecret`/`participantId` unset, key file missing or not an RSA key, bad URL | open the editor with the problem shown at the top; re-check on save |
| Session token | credentials refused, endpoint unreachable | reopen the editor with the registry's answer |
| Participant record | `/participant/search` finds nothing | report (not fatal) |
| Encryption certificate | registry certificate is missing or belongs to another key | **generate a new key + certificate and upload it** to the registry; generate only; upload the current key's certificate; open the editor; continue; quit |
| Registered endpoint | `endpoint_url` does not lead to this gateway | **update the registry** to `publicUrl` or a URL you type; re-test; continue; quit |

The endpoint check POSTs `{"probe": "<random nonce>"}` to
`<endpoint_url>/healthz` and expects `probe_ack`, an HMAC only a gateway
with the same configuration can produce — so a proxy that answers 200 with
something else is caught, and nothing secret travels on the wire. The
listener is started first (or an already-running instance is used), so the
result is about the proxy hop, never about a gateway that was not up.

Without a terminal the same checks run; config, token and certificate
failures exit non-zero with the reason, an endpoint failure is logged as a
warning. Flags: `--no-tui` (never prompt), `--skip-checks` (start
regardless), `--no-banner` / `NHCX_GATEWAY_NO_BANNER=1` (no startup
banner in the logs).

---

## HTTP API

### `POST /out/<nhcx-path>` — send

Requires `Authorization: Bearer <apiKey>` (or `X-Api-Key`).

```sh
curl -s http://127.0.0.1:8090/out/v1/preauth/submit \
  -H "Authorization: Bearer $NHCX_GATEWAY_API_KEY" -H 'Content-Type: application/json' \
  -d '{"recipient": "1000004805@hcx", "fhir": { …Bundle… }}'
```

Envelope fields: `recipient` (required), `sender` (defaults to you),
`correlation_id`, `request_id`, `workflow_id`, `status`, plus the raw
`x-hcx-*` names or an hcxkit-style `jwe_headers` map. Or post the bare
bundle and put `x-hcx-*` values in HTTP headers. Missing ids are minted
(NHCX only accepts UUIDs); `x-hcx-status` defaults to `request.initiated`
(`response.complete` on an `on_` path). A response **must** carry the
request's `correlation_id` — the one thing the adapter cannot infer.

The HTTP status is NHCX's own (202 when accepted); the body reports what
went on the wire:

```json
{ "ok": true, "path": "v1/preauth/submit", "url": "https://…/v1/preauth/submit",
  "headers": { "x-hcx-correlation_id": "…", "x-hcx-api_call_id": "…", … },
  "gateway_status": 202, "response": { …NHCX body… }, "duration_ms": 412, "request_id": "…" }
```

Local failures: `400` bad envelope / no recipient · `401` API key ·
`422` no usable certificate for the recipient (`CERT_NOT_FOUND`,
`SELF_ENCRYPTION_KEY`) · `502` ABDM unreachable or token refused. Shape:
`{"ok": false, "error": {"code", "message", "retryable"}}`.

### `POST /in/<nhcx-path>` (also `POST /v1/…`) — deliver

Register `https://<host>/in` (or the host root) as your registry
`endpoint_url`. NHCX posts `{"payload": "<JWE>"}`; the adapter checks the
message is addressed to you, decrypts, and POSTs to
`callback.url/<nhcx-path>` (or the matching `callback.routes` entry):

```json
{ "meta": { "type": "in", "payloadType": "fhir", "path": "v1/preauth/on_submit", "ip": "…", "time": "…" },
  "jwe_headers": { "x-hcx-sender_code": "…", "x-hcx-correlation_id": "…", "x-hcx-status": "…", … },
  "fhir": { …decrypted Bundle… } }
```

with headers `X-Nhcx-Path`, `X-Nhcx-Payload-Kind`, `X-Nhcx-Correlation-Id`,
`X-Nhcx-Api-Call-Id` and, if set, `Authorization: Bearer <callback.apiKey>`.
Plain-JSON protocol messages (`ProtocolResponse`, `v1/error`) arrive the
same way with `payloadType: "protocol"`. Your 2xx becomes NHCX's `202` with
the acceptance body; anything else makes NHCX retry.

### `GET /ledger…` — the FHIR traffic ledger

See [Ledger](#ledger) below.

### `GET /token` · `POST /token/refresh`

The ABDM session token the gateway holds (for ABDM calls this adapter does
not make), or a freshly minted one. Requires the API key; `Cache-Control:
no-store`.

```json
{ "token": "eyJ…", "token_type": "Bearer", "expires_at": "…", "expires_in": 1187, "refreshed": false }
```

### `GET /healthz` · `GET /readyz`

Liveness; readiness (503 until a session token is held). Unauthenticated.
`POST /healthz` with a probe body is the endpoint check described above.

---

## Ledger

Every message that crosses the gateway is recorded — protected headers,
the bundle, and what happened to it — as one JSON file per message under
`ledger.dir/<yyyy-mm-dd>/` with a per-day index. No database; the index is
loaded at startup and pruned hourly by `retentionDays`.

| Field | Meaning |
| --- | --- |
| `direction` | `out` (your system → NHCX) or `in` (NHCX → your system) |
| `path`, `entity`, `action`, `kind` | `v1/preauth/on_submit` → `preauth`, `on_submit`, `response` |
| `sender`, `recipient`, `correlation_id`, `api_call_id`, `request_id`, `workflow_id`, `hcx_status` | the protected headers |
| `status` | out: `accepted` (NHCX 2xx) · `rejected` (NHCX 4xx/5xx) · `failed` (never dispatched); in: `delivered` · `delivery_failed` (callback refused, NHCX will retry) · `rejected` (undecryptable / wrong recipient) |
| `error` | `{code, message}` when something went wrong |
| `peer` | the far side's answer: NHCX's body (out) or your callback's (in), with URL and HTTP status |
| `redelivery` | in: the same `api_call_id` was seen before — NHCX is retrying |
| `fhir`, `fhir_summary` | the bundle, and a glance at it: resource types, the focus resource (`Claim/cl-1`), its first identifier, the patient, the outcome |

Two behaviours come with it:

- An outbound `on_` response sent without a `correlation_id` is threaded
  automatically to the newest inbound request of the same entity from that
  participant (narrowed by `workflow_id` if given) — the same rule hcxkit
  applies.
- A redelivered callback reaches your backend with `X-Nhcx-Redelivery: true`
  and `meta.redelivery: true`, so idempotency is a header check.

**API** (all behind the API key):

| Endpoint | Returns |
| --- | --- |
| `GET /ledger` | summaries, newest first. Filters: `direction`, `entity`, `kind`, `status`, `sender`, `recipient`, `participant` (either side), `correlation_id`, `workflow_id`, `since`/`until` (RFC 3339, `YYYY-MM-DD`, or `24h`), `limit` (≤500), `before=<id>` for paging (`next_before` is returned when a page is full). |
| `GET /ledger/{id}` | one message in full, bundle and peer response included |
| `GET /ledger/thread/{correlation_id}` | the exchange: every message with that id plus `role` (initiator/responder), `counterparty`, and a derived `state` — `awaiting_response`, `awaiting_our_response`, `partial`, `completed`, `error` |
| `GET /ledger/stats` | totals by direction, status and entity; thread count; span |

Every `/out` answer and every `/in` acknowledgement carries the entry's id
(`ledger_id` / `X-Nhcx-Ledger-Id`).

**CLI** (reads the files directly, no server needed):

```sh
nhcx-gateway ledger list --since 24h --entity preauth --status rejected
nhcx-gateway ledger show 20260826T101512.483920Z-3fa1c2d9
nhcx-gateway ledger thread 0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11
nhcx-gateway ledger stats
```

Add `--json` to any of them for machine-readable output.

**For agents.** The ledger is designed to be read by an AI operator: list
with filters to find what needs attention (`status=delivery_failed`,
`state=awaiting_response` older than an hour), read the thread for the
whole story of one claim, and `fhir_summary` says what a bundle is about
without parsing it. Ids are time-ordered strings, so "everything after X"
is a string comparison.

---

## Command line

```
nhcx-gateway serve    [--no-tui] [--skip-checks] [--no-banner]   check the setup, then listen
nhcx-gateway check    [--no-tui] [--endpoint URL]                check (and offer fixes), then exit 0/1
nhcx-gateway send     --path v1/preauth/submit --recipient CODE [--file bundle.json] [--sender C]
                      [--correlation-id ID] [--workflow-id ID] [--status S]
nhcx-gateway cert     CODE [--refresh]                           print a counterparty's certificate
nhcx-gateway cert generate [--days N] [--force]                  create your key + certificate
nhcx-gateway token                                               print a fresh session token
nhcx-gateway decrypt  [--file jwe-or-callback.json]              decrypt a JWE with your key
nhcx-gateway config init|edit [FILE]                             write the sample / open the editor
nhcx-gateway ledger list|show|thread|stats [--json]              browse the traffic ledger
nhcx-gateway version
```

All commands take `--config FILE` (default `$NHCX_GATEWAY_CONFIG`, then
`./config.json`). `send` and `serve` share one code path, so a `send` that
works means `serve` will. `cert generate` never overwrites without
`--force`, and then keeps the old files as `.bak-<timestamp>`.

---

## Deploying

- **Reverse proxy**: put TLS on nginx/Caddy and forward `https://host/in` →
  `127.0.0.1:8090/in`; set `publicUrl` accordingly. `X-Forwarded-For` is
  not trusted; the peer address is what gets logged.
- **systemd / Docker**: run `serve --no-tui`; the checks still run and a
  failure exits non-zero with the reason. Use `check --no-tui` as a health
  gate before cut-over.
- **Logs**: `text` format shows traffic like
  `12:01:05.123 ▲ OUT v1/preauth/submit → 1000004805@hcx  accepted  nhcx 202  412ms  corr 0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11`
  and `▼ IN … delivered  callback 200`; failures are red with the error code.
  Colour follows the terminal (`NO_COLOR` honoured). Use `json` for collectors.
- **Secrets**: keep them in the environment (`${VAR}`), the key in a
  `@file` with mode 0600. Nothing sensitive is written to logs.
- **Shutdown**: SIGINT/SIGTERM drain in-flight requests for up to 30 s.
- **Token**: refreshed a minute before expiry, on demand when missing, and
  once more on any upstream 401.

---

## Build & release

```sh
make build          # this machine
make check          # vet + race tests
make compile-all    # verify all 11 targets compile
make release        # package all targets into ./dist (+ SHA256SUMS)
```

Targets: Linux amd64/arm64/arm/386 · macOS amd64/arm64 · Windows
amd64/arm64/386 · FreeBSD amd64/arm64. `./scripts/build.sh linux/amd64`
builds one. CI (`.github/workflows/ci.yml`) runs the checks and packages
every target on each push — the archives hang off the workflow run under
*Artifacts* — and on a tag publishes them on the release page:

```sh
git tag v1.0.0 && git push origin v1.0.0
```

produces release **nhcx-gateway v1.0.0** with one archive per platform, a
`SHA256SUMS`, and auto-generated notes. The version inside the binary comes
from `git describe`, so it matches the tag.

---

## Troubleshooting

| You see | It means | Do |
| --- | --- | --- |
| `TOKEN_HTTP_400/401 … Invalid user credentials` | wrong `clientId`/`clientSecret`, or sandbox credentials against production (or vice versa) | fix in `config edit`; check `env` |
| `TOKEN_UNREACHABLE` | session endpoint not reachable | network/proxy; or `auth.mode: get-session` if your onboarding says so |
| `encryption certificate … does NOT match` | registry holds a certificate for another key | pick *generate + upload* in the menu, or *upload the current key's certificate* |
| `CERT_NOT_FOUND` on `/out` | the recipient has no certificate on the registry | they must register one; nothing you can do locally |
| `SELF_ENCRYPTION_KEY` | registry handed out *your* certificate for another code | refresh with `cert CODE --refresh`; contact the registry |
| `registered endpoint … without a probe acknowledgement` | the URL is answered by something other than this gateway (proxy error page, hcxkit, …) | route the path to `listen`; then *update the registry* in the menu or set `publicUrl` |
| `WRONG_RECIPIENT` on `/in` | a message addressed to another participant reached you | check the registry's `endpoint_url` for that participant |
| `DECRYPT_FAILED` on `/in` | encrypted for a key you don't hold | your registered certificate is not this key — run `check` |
| callback returns 4xx/5xx | your backend rejected the delivery | NHCX will retry five times; fix the backend, keep it idempotent |

Verify a counterparty's certificate: `nhcx-gateway cert 1000004805@hcx`.
Inspect a callback you captured: `nhcx-gateway decrypt --file body.json`.
