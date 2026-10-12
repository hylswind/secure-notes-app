# secure-notes

Private Markdown notes for people who sign in with Google, designed to run on an attested Amazon Linux 2023
instance. One static Go binary (`CGO_ENABLED=0`) serves the API, the embedded plain HTML/CSS/JS frontend,
Let's Encrypt (ACME HTTP-01) certificate management, and the privileged data-volume logic.

## Layout

| Path | Purpose |
|---|---|
| `cmd/secure-notes` | entry point: `serve`, `data-volume`, `version` |
| `internal/app` | HTTP server, Google login, sessions, SQLite notes store, ACME, metrics, embedded `web/` |
| `internal/volume` | LUKS2 + NitroTPM data-volume logic (injectable command runner) |
| `system/secure-notes-data.service` | root `Type=oneshot` unit, copied to `dist/system/` |
| `scripts/build.sh`, `scripts/test.sh` | build into `./dist`, offline tests |

Dependencies: `modernc.org/sqlite` (pure Go), `golang.org/x/crypto/acme`, AWS SDK for Go v2 (Secrets Manager).
Google OAuth/OIDC and JWT (RS256) verification use the standard library only.

## Encrypted data volume

`secure-notes-data.service` runs `/opt/app/secure-notes data-volume` as root before the app:

1. Finds the single unused EBS NVMe disk (`lsblk --json`; `DATA_DEVICE` overrides). Zero or several candidates:
   `REFUSED: …`, exit 1.
2. Fresh device: random 64-byte key in a 0600 file under `/run` (deleted afterwards), `cryptsetup luksFormat --type luks2`,
   `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=4+12`, bootstrap slot wiped, opened with the TPM2 token, `mkfs.ext4`,
   mounted on `/data` (`app:app`, 0700). Logs `ENROLLED <device>`.
3. Existing LUKS device: opened with the TPM2 token only; never reformatted, no other keys tried. TPM refusal logs
   `REFUSED: <reason>` and exits 1. Success logs `UNLOCKED <device>`.
4. `/data` already mounted: logs `ALREADY MOUNTED`, exit 0.

The resulting state is written to `/run/secure-notes-volume.state` for `/api/status` and `/metrics`. The unit also lowers
`net.ipv4.ip_unprivileged_port_start` to 80 so the unprivileged `app` user can bind ports 80/443 even if the generated
app unit carries no `CAP_NET_BIND_SERVICE`.

Properties (also shown on the Settings page):

- the volume auto-unlocks on a **reboot** of the same instance;
- it cannot be opened on another instance;
- **stopping and starting** the instance (as opposed to rebooting) discards the TPM storage hierarchy and makes the
  data unrecoverable;
- an image rebuilt with different measurements cannot open an existing volume.

## Configuration

Environment variables (see `SPEC.md`): `DOMAIN`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` (required, from the
environment or the AWS Secrets Manager secret `CONFIG_SECRET_NAME`, default `secure-notes/config`, JSON keys `domain`,
`google_client_id`, `google_client_secret`, `acme_email`, `acme_directory_url`), `ACME_EMAIL`, `ACME_DIRECTORY_URL`,
`HTTP_PORT` (80), `HTTPS_PORT` (443), `DATA_DIR` (`/data`), `DEV_INSECURE_HTTP`.

The HTTP listener and `/healthz` come up first; other routes answer `503 {"error":"not ready"}` until the configuration
is resolved (retried forever with exponential backoff). `/ready` is 200 once configuration, data directory, database and
(outside dev mode) certificate exist.

## Run locally

```sh
./scripts/build.sh
DEV_INSECURE_HTTP=1 HTTP_PORT=8080 DATA_DIR=/tmp/sn DOMAIN=localhost:8080 \
  GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... ./dist/secure-notes serve
```

Register `http://localhost:8080/auth/google/callback` as an authorized redirect URI of the Google OAuth client.

## Tests

`./scripts/test.sh` (or `go test ./...`) runs offline: fake `cryptsetup`/`lsblk`/`mount` runner for the volume logic,
a fake Google (authorization, token, JWKS), a mock ACME directory, a mocked Secrets Manager, and the notes API.
