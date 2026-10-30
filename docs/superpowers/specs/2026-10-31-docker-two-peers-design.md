# Two SPARC peers in Docker

Run two independent SPARC instances on the same Linux device, each with its
own IPv4 address and persistent encrypted identity, for interactive chat and
traffic demonstrations.

## Approach

The user selected Docker rather than loopback addresses, network namespaces,
or virtual machines. Use Docker Compose with a user-defined bridge network.
Proposed addresses are Alice `172.30.50.10` and Bob `172.30.50.11` on
`172.30.50.0/24`; check existing Docker networks and host routes for conflicts
before allocating the subnet.

For the GUI, forward the host's existing X11 display using the local X socket
and a dedicated temporary Xauthority file. This is the proposed default because
the current machine has an X11 session. A browser desktop would add VNC and
browser services; a headless runner would omit the interactive app windows.
Neither is needed for this demonstration.

## Implementation scope

- Add a Dockerfile with Python, Tk, and SPARC's chat and analysis dependencies.
- Add a Compose definition with Alice and Bob on the same bridge. Both can
  listen on port `47655`; no host port publishing or host networking is needed.
- Run as an unprivileged user and keep each peer's data in a separate persistent
  volume. Passphrases are entered through the app, not environment variables.
- Add a Linux launcher that prepares display authorization and starts both
  instances without disabling X11 access control. Keep generated cookies out
  of the image, repository, and logs.
- Document startup, connection settings, shutdown, data retention, and optional
  host-side packet capture. Do not alter SPARC's protocol or GUI behavior.

## Verification

Build the image, validate the Compose configuration, run SPARC's read-only
diagnostic inside both containers, verify their distinct IPs and peer TCP
reachability, and check Tk can connect to the display. Launch the two windows
for the user to create or unlock identities, compare fingerprints, and chat.
Do not create user credentials or claim interactive chat verification without
performing it.

## Limits

The addresses are private container addresses. Internet traffic normally shares
the host's public IP through NAT. This is a same-host simulation and does not
establish physical-device performance or macOS compatibility.
