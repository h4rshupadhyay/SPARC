# Two Docker peers on one Linux desktop

This setup runs SPARC's desktop app in two containers on a private Docker
bridge. It requires a local Linux Docker Engine, Docker Compose, an X11 desktop
(or a local XWayland display), and `xauth`. Docker Desktop, remote Docker
contexts, Windows, and macOS display forwarding are outside this setup's scope.
Run the launcher as your desktop user, without `sudo`.

| Peer | Private IPv4 | Data directory | Docker volume |
| --- | --- | --- | --- |
| Alice | `172.30.50.10` | `/data/alice` | `sparc-lab_alice-data` |
| Bob | `172.30.50.11` | `/data/bob` | `sparc-lab_bob-data` |

## Start and connect

From the repository root:

```sh
./scripts/docker_peers.sh up
```

The first start builds a Python/Tk image with the chat and local analysis
dependencies. Both SPARC windows then open on your desktop. Create an encrypted
identity in each window using a passphrase of at least 15 characters, or unlock
the existing identity on subsequent starts. Passphrases are entered in SPARC;
the launcher does not collect or store them.

Both windows have the normal SPARC title. After unlocking, use **Connection →
Refresh IPs** to identify which has `.10` (Alice) and which has `.11` (Bob).
The `127.0.0.1` address belongs to each container's own loopback interface.

1. In Bob, set **Bind IPv4** to `0.0.0.0` and **Port** to `47655`; start listening.
2. In Alice, set **Peer IPv4** to `172.30.50.11` and **Port** to `47655`; connect.
3. Compare the full fingerprints in both windows and approve first contact on
   each side, then send a synthetic message in **Chat**.

Only one side needs to initiate a connection. To exercise the reverse direction,
disconnect, start Alice's listener, and connect Bob to `172.30.50.10:47655`.
Each container can listen on `47655` because each has its own network stack.
Neither peer's port is published to your Wi-Fi/LAN.

## Wireshark

On the Linux host, capture on **`sparc-br0`**, which appears after startup.
Start capture before connecting if you want the TCP and SPARC handshakes.
Use this **display filter**:

```wireshark
ip.addr == 172.30.50.10 && ip.addr == 172.30.50.11 && tcp.port == 47655
```

You will see both container IPs, TCP ports, packet sizes, timing, and public
handshake fields. Chat contents are encrypted. Follow TCP Stream shows the
public handshake followed by binary encrypted records; SPARC is a custom
protocol, so Wireshark normally labels its traffic TCP rather than TLS.
Capturing only the host's Wi-Fi interface will normally miss this conversation.

If Wireshark lists the interface but reports insufficient capture permissions,
enable Debian/Ubuntu's packaged capture helper:

```sh
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$(id -un)"
```

Select **Yes** when asked whether non-superusers should capture packets. Log
out and back in for the new group membership, then restart the Docker peers
from your desktop terminal. Run Wireshark as your normal user.

This remains a same-host simulation. Both peers normally share the host's
public internet IP through NAT; results do not establish physical-device or
cross-platform network performance.

## Operate and stop

```sh
./scripts/docker_peers.sh status
./scripts/docker_peers.sh check
./scripts/docker_peers.sh logs
./scripts/docker_peers.sh down
```

`check` is read-only and never unlocks or creates identities. `down` removes the
containers, bridge, and generated Xauthority file, while retaining both data
volumes. The next `up` reuses those identities. Re-running `up` recreates both
containers, interrupting active chats; close the windows first to finish work.
Closing a SPARC window stops that peer; the container does not automatically
restart. `up` starts both windows again.

The image runs as an unprivileged user with your host UID/GID. Separate volumes
keep peer data apart, and private directory permissions are enforced by SPARC.
Use the same desktop user for subsequent launches so volume ownership matches.
The generated display cookie is under `.demo/docker/` with private permissions,
is mounted read-only, and is excluded from the Docker build. The launcher does
not change `xhost` access controls. Only run trusted images with desktop access.

## Troubleshooting

- **No window:** run `logs`. Launch from your desktop terminal with the correct
  `DISPLAY` and `XAUTHORITY`; install `xauth` if needed. `up` refreshes the copied
  cookie after a new login session.
- **Docker permission error:** ensure `docker info` works as your normal user.
- **Subnet overlap or existing `sparc-br0`:** check host routes and
  `docker network ls`. If this setup conflicts with another network, choose an
  unused subnet and update the subnet, both fixed IPs, and these instructions
  together. Do not remove unrelated Docker networks.
- **Peer connection fails:** both identities must be unlocked, Bob must be
  listening, and Alice must use Bob's container IP rather than `127.0.0.1`.
- **Review configuration/build only:** use `./scripts/docker_peers.sh config`
  or `./scripts/docker_peers.sh build`; neither opens windows.

