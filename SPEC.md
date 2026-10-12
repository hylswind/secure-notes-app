# secure-notes: private notes on an attested instance

## Purpose

A personal notes web application for people who sign in with Google. Everything it stores (notes,
users, session key, TLS certificate) lives on an extra EBS volume encrypted with LUKS whose key is
sealed to this instance's NitroTPM, so only this instance, booted from this exact image, can read
the data. The app obtains its own HTTPS certificate from Let's Encrypt and reads its configuration
from AWS Secrets Manager through the instance role. It is a realistic exercise of the
spec → generated code → attestable AMI pipeline; follow `CONTRACT.md` for packaging.

## Language and runtime

Go, one static binary (`CGO_ENABLED=0`). Go modules are allowed (for example `golang.org/x/oauth2`,
`golang.org/x/crypto/acme` or `github.com/go-acme/lego`, AWS SDK for Go v2, `modernc.org/sqlite`).
The frontend is plain HTML, CSS and JavaScript embedded in the binary (`embed`) or shipped under
`dist/public`; a bundler may be used only through `packages.build`; nothing from Node.js at run
time. `packages.runtime` contains only what the data-volume unit needs (`cryptsetup`, `tpm2-tss`,
`e2fsprogs`, `util-linux`). The service listens on ports 80 and 443 as user `app`; the systemd unit
grants `CAP_NET_BIND_SERVICE`.

`exec` is `/opt/app/secure-notes serve`. The privileged data-volume logic is either a subcommand of
the same binary (`/opt/app/secure-notes data-volume`) or a shell script under `/opt/app/system/`.

## Encrypted data volume (privileged unit)

Ship `dist/system/secure-notes-data.service` and list it in `app.yaml` under `system.units`. It is
a root-run `Type=oneshot`, `RemainAfterExit=yes` unit; the app's unit requires it.

1. **Discover the device**: the one EBS NVMe namespace that is not the root disk and has no
   partition or filesystem in use (use `lsblk --json`; `/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_*`
   names are available). The environment variable `DATA_DEVICE` overrides discovery. Zero or more
   than one candidate: log `REFUSED: <reason>` and exit 1.
2. **Fresh device** (not LUKS): generate a 64-byte random key in memory (a file under `/run`,
   mode 0600, deleted afterwards), `cryptsetup luksFormat --type luks2` with it,
   `systemd-cryptenroll --unlock-key-file=<file> --tpm2-device=auto --tpm2-pcrs=4+12 <device>`,
   then remove the bootstrap key slot (`--wipe-slot=password`), open the volume with the TPM2 token
   (`/usr/lib/systemd/systemd-cryptsetup attach secure-notes-data <device> - tpm2-device=auto`),
   `mkfs.ext4`, mount at `/data`, `chown app:app /data`, `chmod 700 /data`. Log one line
   `ENROLLED <device>`.
3. **Existing LUKS device**: open with the TPM2 token only. If the TPM refuses (PCR mismatch, a
   different instance, state lost after stop/start) log `REFUSED: <reason from the tool>` and exit 1.
   Never reformat, never try other keys. On success mount at `/data`, log `UNLOCKED <device>`.
4. **Idempotent**: if `/data` is already a mount point, log `ALREADY MOUNTED` and exit 0.

Document these properties in `README.md` and on the app's Settings page: the volume auto-unlocks on
a reboot of the same instance; it cannot be opened on another instance; stopping and starting the
instance (as opposed to rebooting) discards the TPM storage hierarchy and makes the data
unrecoverable; an image rebuilt with different measurements cannot open an existing volume.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `DOMAIN` | yes | public DNS name, used for ACME and OAuth redirect |
| `GOOGLE_CLIENT_ID` | yes | OAuth client id |
| `GOOGLE_CLIENT_SECRET` | yes | OAuth client secret |
| `ACME_EMAIL` | no | contact for Let's Encrypt notices; account is created without contact when unset |
| `ACME_DIRECTORY_URL` | no | default Let's Encrypt production; staging for tests of real issuance |
| `HTTP_PORT` / `HTTPS_PORT` | no | 80 / 443 |
| `DATA_DIR` | no | `/data` |
| `CONFIG_SECRET_NAME` | no | `secure-notes/config` |
| `DEV_INSECURE_HTTP` | no | `1` = plain HTTP on `HTTP_PORT` only, no ACME; for tests and local runs |

Values missing from the environment are read once from the AWS Secrets Manager secret named by
`CONFIG_SECRET_NAME` (JSON object with keys `domain`, `google_client_id`, `google_client_secret`,
optional `acme_email`, `acme_directory_url`) using the SDK default credential chain, i.e. the
instance role. Start-up order: open the HTTP listener and answer `/healthz` first; resolve the
configuration with retries and exponential backoff (log each failure, never exit); until resolved,
every other route answers `503 {"error":"not ready"}`. `/ready` answers 200 only when configuration,
data directory, database and (outside dev mode) certificate are all in place.

## Keys, certificate, TLS

- First start creates `DATA_DIR/keys.json` (0600) with a random 32-byte session signing key; it is
  reused afterwards. `DATA_DIR` is on the encrypted volume, so keys and certificates survive reboots.
- ACME (HTTP-01) against `ACME_DIRECTORY_URL` for `DOMAIN`; account key, certificate, private key
  and renewal state under `DATA_DIR/acme/`. HTTPS starts as soon as a valid certificate exists;
  renewal is attempted daily when less than 30 days remain; failures are logged and retried with
  backoff, never fatal.
- Port 80 serves `/.well-known/acme-challenge/*` and `/healthz`; everything else redirects to
  `https://DOMAIN/...`. Port 443 serves the app with TLS 1.2+ and HSTS.

## Google login

- `GET /auth/google` redirects to Google's authorization endpoint with scopes `openid email profile`,
  a random `state` bound to a short-lived cookie, and PKCE.
- `GET /auth/google/callback` validates `state`, exchanges the code with the client secret, verifies
  the ID token (`iss` is `accounts.google.com` or `https://accounts.google.com`, `aud` is the client
  id, not expired, `email_verified` true), upserts the user (Google `sub` as primary key, email,
  display name), issues an HttpOnly, Secure, SameSite=Lax session cookie signed with the session key,
  valid 14 days, and redirects to `/app`.
- `POST /auth/logout` clears the session. Unauthenticated requests to `/app` and `/api/*` get a
  redirect (pages) or `401 {"error":"unauthorized"}` (API).
- Users are matched to shares by email; a user who logs in sees notes shared with that email.

## Notes

Storage: SQLite database `DATA_DIR/notes.db` (WAL mode). Note fields: `id` (random, URL-safe),
`owner` (Google `sub`), `title` (1–200 characters), `body` (Markdown, at most 100 KB), `tags`
(0–20, each `[a-z0-9-]{1,30}`, unique), `created_at`, `updated_at` (RFC 3339 UTC), `deleted_at`
(null, or the time it was moved to trash). A daily job purges notes trashed more than 30 days ago.

JSON API (all require a session):

| Method | Path | Behaviour |
|---|---|---|
| GET | `/api/me` | `{sub_suffix, email, name}` |
| GET | `/api/notes` | own notes; query `q` (full-text over title and body), `tag`, `trash=1`; sorted by `updated_at` desc; `page`, `page_size` (default 50, max 200) |
| POST | `/api/notes` | create → `201` |
| GET | `/api/notes/{id}` | own or shared-with-me note; `404` otherwise |
| PUT | `/api/notes/{id}` | owner only; body must include the `updated_at` the client last saw; mismatch → `409 {"error":"conflict","note":{…}}` |
| DELETE | `/api/notes/{id}` | owner only; moves to trash; `?permanent=1` deletes immediately |
| POST | `/api/notes/{id}/restore` | owner only; out of trash |
| GET | `/api/notes/{id}/shares` | owner only; list of `{email, created_at}` |
| POST | `/api/notes/{id}/shares` | owner only; body `{email}`; read-only share; sharing with yourself is `400` |
| DELETE | `/api/notes/{id}/shares/{email}` | owner only; revoke |
| GET | `/api/shared` | notes shared with the current user's email, same filters as `/api/notes` |
| GET | `/api/status` | `{volume: "UNLOCKED"|"ENROLLED"|"REFUSED"|"DEV", volume_reason, certificate_expires_at, version}` |

Validation errors are `400 {"error":"<field>: <message>"}`; access to someone else's note is `404`.

## Frontend

Served by the same binary, no CDN, CSP `default-src 'self'`.

- `/`: landing page with a short explanation and "Sign in with Google"; redirects to `/app` when
  already signed in.
- `/app`: notes list (search box, tag filter chips, "Trash" and "Shared with me" views) and an editor
  pane: title, tags input, Markdown textarea with live preview, autosave 2 s after the last change,
  explicit Save, a visible conflict message with "reload their version" when the server answers
  `409`. Trash view offers Restore and Delete permanently. Shared notes open read-only.
- Share dialog on a note: add an email, list current shares, revoke.
- `/app/settings`: account (name, email), Logout, data-volume status from `/api/status`, certificate
  expiry, and the volume limitations text from the data-volume section.
- Usable at 360 px width, keyboard accessible, no inline scripts.

## Operational

- `/healthz` (200 as soon as the HTTP listener is up), `/ready` (see Configuration).
- `/metrics`, Prometheus text format, at least `http_requests_total{method,route,status}`,
  `logins_total{result}`, `notes_total`, `acme_certificate_expiry_seconds`, `data_volume_state`
  (0 unknown, 1 unlocked, 2 enrolled, 3 refused, 4 dev).
- One JSON log line per request (time, method, route, status, duration_ms); never log emails, note
  content, tokens or keys. Background events (config resolved, ACME, purge, volume state) also as
  JSON lines.
- SIGTERM / SIGINT: stop accepting, finish in-flight requests within 10 s, close the database, exit 0.

## Tests

`go test ./...` runs offline with `DEV_INSECURE_HTTP=1` and a temporary `DATA_DIR`, and covers:

- Data-volume logic with fake `cryptsetup`, `systemd-cryptenroll`, `systemd-cryptsetup`, `lsblk`,
  `mkfs.ext4` and `mount` placed on `PATH` (or an injected command runner): fresh device, existing
  LUKS device that unlocks, TPM refusal, zero candidates, two candidates, already mounted; assert
  that an existing LUKS device is never formatted.
- Google OAuth: an in-process fake Google (`httptest.Server` for the authorization and token
  endpoints and a JWKS); full login, bad `state`, bad `aud`, expired token, `email_verified` false.
- Session cookie: sign, verify, tamper, expiry.
- Configuration: environment overrides a mocked Secrets Manager client; retry on failure; readiness.
- ACME: client against an in-process mock ACME directory (new nonce, new account, new order,
  HTTP-01 challenge answered by the app's own listener, finalize, certificate download) and the
  renewal decision at the 30-day boundary.
- Notes API: create, read, update, trash, restore, permanent delete, validation of every field,
  tags, search, pagination, sharing, revocation, access by a non-owner, `409` on stale `updated_at`,
  purge of old trash with an injectable clock.
- `/metrics` format and `/api/status` values.
