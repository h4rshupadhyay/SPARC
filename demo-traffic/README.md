# Traffic Analysis demo captures

Open these files in SPARC's **Traffic Analysis → Open Capture**, then click
**Analyze**. Select **Capture rate** to view the traffic over time. You can
also open the originals in Wireshark. The `*-report.json` files beside them
are reference reports from SPARC's offline analyzer, not capture inputs.

| Capture | Contents | Useful display filter |
| --- | --- | --- |
| `mixed-protocols.pcap` | Deterministic five-packet test fixture: IPv4 TCP, IPv4 UDP, ARP, and IPv6 UDP over four seconds | `tcp`, `udp`, `arp`, or `ipv6` |
| `sparc-chat.pcapng` | Real SPARC handshake, encrypted demo messages, delivery receipts, and TCP teardown between the Docker peers | `tcp.port == 47701` |
| `sparc-images.pcapng` | Real SPARC handshake and verified encrypted transfers of the Earth and Moon JPEG samples | `tcp.port == 47702` |

The two real captures were recorded on `sparc-br0` between `172.30.50.10`
(Alice container) and `172.30.50.11` (Bob container). Additional temporary
SPARC services used ports **47701/47702** and disposable identities; the open
GUI sessions and their identities were not used. Only demonstration messages
and the NASA sample images were transferred. These are same-host Docker
measurements, with possible large packets from host offloading, rather than
measurements of a physical network. Encrypted application content will not
appear as readable chat or JPEG data in Wireshark.

`mixed-protocols.pcap` is copied unchanged from
`tests/fixtures/traffic-small.pcap`. Its expected totals are five packets,
262 captured frame bytes, and a four-second first-to-last interval. Its test
addresses (`10.0.0.1`, `10.0.0.2`, and `2001:db8::1/::2`) differ from the
Docker addresses. It is synthetic and is not a recording of a SPARC session.

From the repository root, copy the folder to running peers without a restart:

```sh
docker compose cp demo-traffic/. alice:/data/demo-traffic
docker compose cp demo-traffic/. bob:/data/demo-traffic
```

In each container, browse to `/data/demo-traffic/` in **Open Capture**. These
files persist in the peer data volumes across `down` and `up`. The Docker
image includes TShark and PyShark for offline analysis; capture privileges
are not needed to analyze saved files. The normal interactive app listener
still uses port **47655**.
