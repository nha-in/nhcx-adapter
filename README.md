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

Release archives (see [Build & release](#build--release)) also carry four
launcher scripts — `serve`, `serve-hidden`, `stop`, `update` (`.bat` on
Windows, `.sh` elsewhere) — so a server can be started in the background,
stopped, and moved to another version without remembering any flags. See
[Running from an archive](#running-from-an-archive) and [Updating](#updating).

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
| `participant.name` | — | A label for logs and the banner. Cosmetic. |
| `participants[]` | `[]` | Additional identities this gateway holds; see [Hosting several participants](#hosting-several-participants). |
| `participant.clientId` / `clientSecret` | — | ABDM credentials from onboarding. |
| `participant.privateKey` | — | RSA key of your registered certificate: PEM, base64 PEM or `@file`. |
| `callback.url` | — | Where decrypted messages are POSTed. Per participant under `participants[].callback`. |
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

### Hosting several participants

One process can be more than one participant. The top-level `participant` is
the default; each entry in `participants` is another identity, with its own
registry code and its own callback:

```json
{
  "participant": {
    "participantId": "1000003463@hcx",
    "clientId": "${NHCX_CLIENT_ID}",
    "clientSecret": "${NHCX_CLIENT_SECRET}",
    "privateKey": "@private_key.pem"
  },
  "participants": [
    { "participantId": "1000004805@hcx", "name": "Dummy IRDAI Payer",
      "callback": { "url": "http://127.0.0.1:8082/nhcx/callback" } },
    { "participantId": "1000001518@hcx", "name": "PMJAY",
      "callback": { "url": "http://127.0.0.1:8090/nhcx/callback" },
      "clientId": "…", "clientSecret": "…", "privateKey": "@pmjay_key.pem" }
  ],
  "callback": { "url": "http://127.0.0.1:8765/nhcx/callback" }
}
```

**What a hosted entry needs is just a code and a callback.** Everything else
is inherited from the default profile — credentials, private key, and every
callback field it does not set (`apiKey`, `timeoutSeconds`, `appendPath`,
`routes`). The second entry above is the fully-specified form: its own ABDM
credentials and its own certificate.

`callbackUrl` is accepted as a synonym for `callback.url`, so an hcxkit
`participants` array can be pasted across unchanged.

What changes with more than one participant:

| | |
| --- | --- |
| **Inbound** | The `x-hcx-recipient_code` in the JWE picks the participant. Its key decrypts (the others are tried as a fallback), its callback receives the delivery, and its `callback.apiKey` is the bearer token. A code no profile holds is refused with `WRONG_RECIPIENT`, which names every code this gateway does hold. |
| **Outbound** | `x-hcx-sender_code` picks who sends: that participant's code goes in the protected header and its credentials mint the session token. Unset, it is the default profile — unchanged from a single-participant gateway. |
| **Sessions** | One per distinct `clientId`. Profiles that inherit the default's credentials share its token rather than opening a second session for the same client. |
| **Delivery envelope** | `meta.participant` names the addressee, and the callback also gets it as `X-Nhcx-Participant`. |
| **`GET /token`** | `?participant=<code>` returns that identity's token. An unknown code is a 404 rather than a silent fallback. |
| **`nhcx-gateway token`** | `--participant <code>` does the same on the command line. |
| **Startup checks** | Each hosted participant gets its own line: its credentials must mint a session, and the registry certificate for its code must match the key it will decrypt with. |
| **Ledger** | Unchanged — `sender` and `recipient` were already recorded, so `GET /ledger?participant=<code>` filters one identity's traffic. |

Encrypting for a code this gateway itself holds is allowed (a loopback test,
or one hosted participant writing to another); encrypting for an outside
participant with one of our own certificates is still refused as
`SELF_ENCRYPTION_KEY`.

The interactive repair flow — generate a certificate, re-register an
endpoint — acts on the default profile. A hosted participant whose
certificate does not match is reported at startup and fixed by registering
its certificate yourself.

### The editor

`nhcx-gateway config edit` is a full-screen form over the default profile and
the shared sections. The `participants` array is edited by hand; the editor
preserves it. Otherwise:
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
nhcx-gateway update   [--list] [--check] [--latest] [--to TAG] [-y] [--prerelease]
                                                                 list GitHub releases; upgrade or downgrade
nhcx-gateway version
```

All commands take `--config FILE` (default `$NHCX_GATEWAY_CONFIG`, then
`./config.json`). `send` and `serve` share one code path, so a `send` that
works means `serve` will. `cert generate` never overwrites without
`--force`, and then keeps the old files as `.bak-<timestamp>`.

---

## Running from an archive

Every release archive holds the binary, this README, `config.sample.json`
and four scripts that wrap the binary for day-to-day use. They live next to
the binary and `cd` there themselves, so they work from any directory or a
double-click.

| Windows | Linux / macOS / FreeBSD | Does |
| --- | --- | --- |
| `serve.bat` | `./serve.sh` | `nhcx-gateway serve` in this window; Ctrl+C stops it. Extra arguments pass through (`serve.bat --skip-checks`). |
| `serve-hidden.bat` | `./serve-hidden.sh` | Starts `serve --no-tui` in the background with no window/terminal. Output goes to `logs/nhcx-gateway.log` (the previous run is kept as `logs/nhcx-gateway.prev.log`), the process id to `nhcx-gateway.pid`. Waits a few seconds and, if the startup checks failed, prints the tail of the log. Refuses to start a second instance. |
| `stop.bat` | `./stop.sh` | Stops the background server: asks it to shut down (in-flight requests drain for up to 30 s), then forces it. Without a pid file it falls back to finding the process by name. |
| `update.bat` | `./update.sh` | `nhcx-gateway update` with the same arguments, then reminds you to `stop` + `serve-hidden` if a server is running on the old version. |

The Windows hidden start uses `powershell Start-Process -WindowStyle Hidden`,
which is present on every supported Windows; nothing is installed as a
service. For a service or boot-time start use Task Scheduler / NSSM
(`serve-hidden.bat` as the action) or systemd on Linux — see below.

---

## Updating

`nhcx-gateway update` looks at the GitHub releases of this project and
installs whichever one you pick in place of the running binary — newer
**or older**, so a bad release is a one-command rollback.

```
$ nhcx-gateway update
fetching releases from github.com/nha-in/nhcx-adapter…
installed v1.0.0 linux/amd64
latest    v1.2.0 — update available

  v1.2.0         2026-09-02 latest          ◀ pick one; older = downgrade
  v1.1.0         2026-08-20
  v1.0.0         2026-08-10 installed
  v0.9.0         2026-08-01
  cancel
```

In a terminal it is an arrow-key menu with a confirmation that shows the
release notes; pick a version and it downloads the archive for this
OS/architecture, checks it against the release's `SHA256SUMS`, swaps the
binary (written beside the old one and renamed into place, so a failed
download never leaves a broken install), and runs the new binary's
`version` to prove it starts. **The running server keeps its version until
restarted** — `stop` + `serve-hidden` (or your service manager) switches.

| Flag | |
| --- | --- |
| `--list` | print every release with *latest* / *installed* / *pre-release* / *no build for this platform* marks, and exit |
| `--check` | print installed vs latest; exit **1** when a newer release exists (for cron / monitoring) |
| `--latest` | install the newest stable release; says *already up to date* otherwise |
| `--to v1.1.0` | install that tag, whichever direction that is (`1.1.0` works too) |
| `-y` / `--yes` | no confirmation |
| `--prerelease` | include pre-releases (`v2.0.0-rc1`) in the list and as `--latest` |
| `--repo owner/name` | consult another repository |

Without a terminal (`serve-hidden`, cron, CI) only `--latest` / `--to` /
`--list` / `--check` work; there is nothing to ask.

`serve` also checks once at startup, in the background with a 15 s cap, and
logs `update available installed=v1.0.0 latest=v1.2.0` if there is one — it
never blocks or fails the start. Turn that off with `--no-update-check` or
`NHCX_GATEWAY_NO_UPDATE_CHECK=1`.

Environment: `NHCX_GATEWAY_UPDATE_REPO` (default `nha-in/nhcx-adapter`),
`GITHUB_TOKEN` / `NHCX_GATEWAY_GITHUB_TOKEN` (needed for a **private**
repository, otherwise only raises the API rate limit),
`NHCX_GATEWAY_GITHUB_API` (GitHub Enterprise base URL). The binary has to be
writable by the user running `update`; a `/usr/local/bin` install owned by
root needs `sudo nhcx-gateway update`. On Windows the previous binary is
parked as `nhcx-gateway.exe.old` while a server still runs it and deleted at
the next start. Dev builds (`version` shows something other than a tag)
list releases but never report *update available*, since there is nothing
to compare.

---

## Deploying

- **Background on a plain box**: `serve-hidden` / `stop` from the archive
  (above). Logs land in `logs/`.
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
from `git describe`, so it matches the tag. Each archive contains the
binary, `README.md`, `config.sample.json` and the launcher scripts from
`scripts/pkg/windows/*.bat` or `scripts/pkg/unix/*.sh`. `nhcx-gateway
update` relies on exactly this layout — the archive name
`nhcx-gateway_<tag>_<os>_<arch>.tar.gz|.zip` and the `SHA256SUMS` — so keep
it if you fork the release process, and point `NHCX_GATEWAY_UPDATE_REPO`
(or `-X nhcx-gateway/internal/update.DefaultRepo=…` at build time) at your
repository.

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
