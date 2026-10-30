# Docker Two Peers Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Alice and Bob as interactive SPARC peers with distinct Docker IPs.

**Architecture:** One non-root Python/Tk image, two Compose services on a bridge,
and separate named data volumes. A Linux launcher supplies scoped X11 cookie
authorization and lifecycle commands. Existing app behavior stays unchanged.

**Tech Stack:** Debian Bookworm, Python 3.11, Tk, Docker Compose, Bash, Xauthority.

**Spec:** `docs/superpowers/specs/2026-10-31-docker-two-peers-design.md`

## Global Constraints

- Alice `172.30.50.10`, Bob `172.30.50.11`, subnet `172.30.50.0/24`.
- Separate persistent identities; unprivileged processes; no host port publishing.
- Local Linux X11 display; retain X11 access control; never log cookies.
- No protocol or GUI behavior changes; no generated user credentials.

## Review Focus

- An unavailable display must fail clearly before starting containers.
- X11 cookies and existing identity files must stay outside build context.
- Named data volumes must be writable by the image's non-root user.
- Repeated startup must mount the current display cookie; shutdown must retain data.
- Missing dependencies and invalid commands must fail without changing the stack.

### Task 1: Container image and two-peer network

**Files:** Create `Dockerfile`, `.dockerignore`, `compose.yaml`.

**Interfaces:** Produce image `sparc-lab:local`, Compose project `sparc-lab`,
services `alice`/`bob`, bridge `sparc-br0`, and data volumes per peer.
Consume `SPARC_UID`, `SPARC_GID`, `SPARC_XAUTHORITY`, and `DISPLAY` from launcher.

- [x] Add allowlisted build context, Python/Tk image, and Compose services.
- [x] Run Compose configuration validation and build the image.
  Expected: both succeed; no identity or cookie files enter the context.

### Task 2: Launcher, operating guide, and runtime verification

**Files:** Create `scripts/docker_peers.sh`, `docs/docker-peers.md`; update `README.md`.

**Interfaces:** Launcher supports `up`, `down`, `status`, `logs`, `check`, `build`,
and `config`; consumes the image and Compose definition from Task 1.

- [x] Add private Xauthority preparation, dependency/display checks, and commands.
- [x] Document GUI pairing, Wireshark interface/filter, shutdown, and data retention.
- [x] Check shell syntax and failure paths (invalid command, missing DISPLAY).
  Expected: clear errors, no stack mutation.
- [x] Build and launch both peers; run read-only diagnostics and a withdrawn Tk probe.
  Expected: two running peers, display access, no generated identities.
- [x] Exchange synthetic TCP probe data across the bridge and inspect endpoint IPs.
  Expected: `.10` and `.11` visible to one another, both directions reachable.
- [x] Check retained data permissions and repeat startup/shutdown behavior using
  a disposable non-identity marker; leave both windows running for the user.
- [x] Run applicable existing tests and a fresh independent review; address material findings.

## Execution notes

User approved proceeding with the setup. Implement inline in the current
checkout on a dedicated branch; leave the changes available for review.
This is infrastructure configuration: use real image/runtime checks rather
than tests that assert the contents of YAML or Dockerfile instructions.
