
# N1 — DEAD SIGNAL

**PARSEC · IIT Dharwad · Veni Vidi Vici CTF**

## 1. Overview

N1 — DEAD SIGNAL is a Foundation-level network reconnaissance challenge.

Participants investigate a fictional Meridian Systems development portal,
discover exposed deployment artifacts, reconstruct the application's
service architecture, and identify a development diagnostic interface.

The challenge teaches progressive information discovery rather than
relying on a complex exploit or a known CVE.

## 2. Requirements

- Docker Engine
- Docker Compose v2 (`docker compose`)
- curl
- grep
- Docker CLI access for the smoke tests

Participants do not download virtual machines, Docker images, or
multi-gigabyte artifacts. The challenge runs on the organizer's host.

## 3. Start the environment

From the project root:

    docker compose config
    docker compose build
    docker compose up -d
    docker compose ps

Open the portal:

    https://localhost:8443/

The certificate is self-signed, so a certificate warning is expected
in a local browser.

HTTP on port 8080 redirects to HTTPS on port 8443.

## 4. Run the tests

Run:

    ./tests/smoke.sh

The smoke tests verify:
- HTTP to HTTPS redirect
- Main portal availability
- Backup discovery through robots.txt
- Backup artifact availability
- First flag in the deployment manifest
- API diagnostics through the gateway
- Second flag in the diagnostic endpoint
- No host-published port for the Research API

## 5. Stop and reset

Stop the containers:

    docker compose down

Rebuild and recreate them:

    docker compose down
    docker compose up -d --build --force-recreate

The challenge currently uses static flags and does not maintain
participant-specific state.

## 6. Intended solve path

1. Enumerate the target's exposed services.
2. Identify the web server and inspect the portal.
3. Read `/robots.txt`.
4. Follow the `/backup/` path.
5. Inspect the dated deployment artifacts.
6. Find the deployment verification token in `deployment.json`.
7. Read the archived Compose and Nginx configurations.
8. Infer that `/api/` is forwarded to the internal Research API.
9. Enumerate `/api/diagnostics/` and `/api/diagnostics/status`.
10. Inspect `/api/diagnostics/artifacts/latest` to find the final flag.

## 7. Architecture

The gateway publishes host ports 8080 and 8443. It is connected to
both the public and internal Docker networks.

The Research API is connected only to the internal Docker network.
It has no `ports:` mapping, so Docker does not publish its port
on the host.

The gateway forwards requests under `/api/` to the Research API.

    Participant
        |
        | HTTP / HTTPS
        v
    Nginx gateway
        |
        | Internal Docker network
        v
    Research API :8080

## 8. Flags

### Flag 1

    FLAG{VVV_N1_EXPOSED_DEPLOYMENT}

Location: the exposed development deployment manifest.

Learning objective: recognize that deployment artifacts can disclose
sensitive metadata and verification material.

### Flag 2

    FLAG{VVV_N1_DEBUG_INTERFACE}

Location: the development diagnostics artifact endpoint.

Learning objective: connect information disclosed by deployment
configuration to functionality exposed through a reverse proxy.

These flags are development placeholders. Replace them before the
competition and integrate validation with the selected CTF platform.

## 9. Safety and deployment notes

- All organizations and deployment metadata are fictional.
- SSH is intentionally omitted.
- The API runs as a non-root user.
- The API container drops Linux capabilities and enables
  no-new-privileges.
- The API is not published on a host port.
- Docker network isolation is one layer of defense, not a substitute
  for host security or deployment hardening.

Do not expose this prototype publicly without reviewing TLS,
rate limiting, monitoring, flag validation, reset behavior,
resource limits, and participant isolation.

## 10. Project layout

    N1-dead-signal/
    ├── docker-compose.yml
    ├── .dockerignore
    ├── README.md
    ├── gateway/
    │   ├── Dockerfile
    │   ├── nginx.conf
    │   ├── web/
    │   │   ├── index.html
    │   │   └── robots.txt
    │   └── artifacts/
    │       ├── index.html
    │       └── 2026-09-28/
    │           ├── index.html
    │           ├── README.md
    │           ├── deployment.json
    │           ├── docker-compose.yml
    │           └── nginx-default.conf
    ├── research-api/
    │   ├── Dockerfile
    │   └── app.py
    └── tests/
        └── smoke.sh
