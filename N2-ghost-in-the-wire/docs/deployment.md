# N2 — Ghost in the Wire · Deployment & Security

## 1. Build & run

### Local (no Docker)

```bash
cd N2-ghost-in-the-wire
pip install scapy
python3 organizer/generate_evidence.py
python3 organizer/generate_capture.py
python3 portal/app.py                 # http://0.0.0.0:8080
```

### Docker Compose

```bash
cp .env.example .env                   # set CTFD_URL / PUBLIC_PORT if desired
docker compose build
docker compose up                      # portal only (no host port published)

# with the optional nginx gateway exposing a public port:
docker compose --profile gateway up    # http://localhost:${PUBLIC_PORT:-8080}
```

If the shared VVV public gateway already fronts challenges, run the portal
service alone (`docker compose up portal`) and have the shared gateway proxy
to `n2-portal:8080` (the internal service name on the `n2net` network) or to
the published port.

## 2. Reset / regenerate

The challenge is fully deterministic. To reset to a known-good state:

```bash
rm -rf evidence/*.pcap evidence/*.log evidence/*.csv
rm -f organizer/_manifest.json organizer/_artifact_envelope.bin organizer/flag_config.json
python3 organizer/generate_evidence.py
python3 organizer/generate_capture.py
```

Re-running produces byte-identical evidence and pcap (fixed seed `20261028`).
Restarting the container does **not** change the evidence or flags, because
they are baked into the image and the read-only `evidence/` mount.

## 3. Resource limits

Defined in `docker-compose.yml`:

| Service | CPU limit | Memory limit | CPU reserve | Memory reserve |
|---|---|---|---|---|
| portal | 0.50 | 128M | 0.10 | 32M |
| gateway | 0.30 | 64M | 0.05 | 16M |

The portal is a stdlib `http.server` with no runtime dependencies, so 128M is
generous headroom.

## 4. Security review

### Isolation of organizer material
- `portal/Dockerfile` copies **only** `portal/` and `evidence/`. It never
  copies `organizer/`, `tests/`, `docs/`, or any `_*.json` / `_*.bin`.
- `organizer/flag_config.json`, `_manifest.json`, `_artifact_envelope.bin`,
  `generate_evidence.py`, `official_solve.py`, and `solution.md` are
  unreachable from the portal container.

### Path traversal / directory exposure
- The portal serves evidence files from a **hard allowlist** of four
  filenames. Any other path returns 404.
- Verified against `GET /evidence/../organizer/generate_evidence.py` and
  `GET /evidence/%2e%2e/organizer/flag_config.json` (both 404), and against
  `GET /organizer/flag_config.json` (404).
- Static assets are restricted to known extensions and reject any path
  containing `/` or `..`.
- No directory listing is implemented.

### Flag exposure
- `tests/flag_validation.py` scans every file under `evidence/`, `portal/`, and
  `docs/` for the flag strings and for any stray `VVVFLAG{...}` token. None are
  found (the only `VVVFLAG` text in the portal HTML is the literal format
  example `VVVFLAG{...}` shown to participants, which is intentional).
- Flag 2 differs from the audit-log artifact id, so the audit log is not a
  shortcut to Flag 2.

### Container hardening
- Portal runs as non-root user `n2portal` (uid 10001).
- `read_only: true` root filesystem; only `/tmp` is writable (tmpfs).
- `security_opt: ["no-new-privileges:true"]` on both services.
- No Docker socket mounts, no host mounts other than the read-only `evidence/`
  volume, no `--privileged`.
- No published ports on the portal itself; only the optional gateway publishes
  one port.
- HTTP security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Cache-Control: no-store`) are set on every response, by
  both the portal and nginx.

### No real exfiltration
- The challenge is entirely forensic. The pcap is synthesized with scapy; no
  packet is ever sent on a real network. The exfil domain
  (`sync.ghostwire.test`) is a reserved `.test` TLD and is never resolved.

## 5. Acceptance tests

```bash
./tests/smoke.sh                          # full pipeline (generate→solve→test)
python3 tests/evidence_consistency.py     # cross-source agreement
python3 tests/payload_reconstruction.py   # base64url round-trip + ordering
python3 tests/flag_validation.py          # flag derivation + leak scan
```

At implementation time all 51 checks pass. See the completion report section
below for the recorded output.

## 6. Completion report (sandbox run, 2026-11-01)

- **Sandbox has no Docker.** `docker compose` could not be executed here.
  Verification was done by running `portal/app.py` directly and curling every
  route; the full generate→solve→test pipeline ran via `tests/smoke.sh`.
- **Evidence size:** `network_capture.pcap` = 21,917 bytes (~21 KiB, well
  under the 5 MB target). Resolver log 8.9 KiB; audit log 1.7 KiB; DHCP CSV
  871 B.
- **Official solve:** both flags recovered; envelope `content_sha256`
  integrity check PASS; flags match `organizer/flag_config.json`.
- **Tests:** `evidence_consistency` 29/29, `payload_reconstruction` 11/11,
  `flag_validation` 11/11 — **51/51 pass**.
- **Portal routes verified:** `/` 200, `/evidence/*` 200 for all four files,
  `/static/style.css` 200, traversal attempts 404, organizer paths 404,
  `POST /` 405, unknown route 404. Security headers present.

## 7. Unresolved limitations

1. **Docker not exercised in this sandbox.** The compose file, Dockerfiles,
   healthcheck, and resource limits are written to spec but were not built/run
   here. A host with Docker should run `docker compose --profile gateway up`
   and `./tests/smoke.sh` before competition day. The standalone `app.py` run
   is a faithful proxy for the container behavior (same code, same filesystem
   layout, same env vars).
2. **Blind-solve tests not performed here.** The spec asks for at least two
   independent testers; that requires human participants and is out of scope
   for an autonomous build. The official solve script and the four test suites
   are the deterministic substitute.
3. **Single-platform images.** Dockerfiles use `python:3.12-slim` and
   `nginx:1.27-alpine` (linux/amd64 by default). Multi-arch builds can be added
   via `docker buildx` if the VVV host runs arm64.
4. **No CTFd integration code.** Per spec, flag submission is delegated to the
   shared VVV platform; the portal only links to `CTFD_URL`. If an independent
   submission endpoint is later required, it must be added to a separate
   service, not the evidence portal.
