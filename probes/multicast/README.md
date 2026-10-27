# Multicast probe

`probe.c` measures, on each system, what multicast a program can do: which
ways of joining a group each kind of socket accepts, whether a datagram sent
to the group then arrives, the sending options (TTL / hop limit, loopback,
the outgoing interface), two sockets sharing a port, and whether a socket
receives a group's datagrams only another socket joined. It runs on the four
CI machines (`.github/workflows/multicast-probe.yml`), by hand or when it
changes.

The kinds of socket: **v4** (`AF_INET`), **v6only** (`AF_INET6`,
`IPV6_V6ONLY` 1) and **dual** (`AF_INET6`, `IPV6_V6ONLY` 0: IPv6 and IPv4 on
one socket, what `UDPSocket` and `MulticastSocket` open without an address).
Groups: `239.255.42.99` (IPv4) and `ff12::4299` (IPv6).

## Results (27/10/2026: ubuntu-24.04, macos-15, macos-15-intel, windows-2022)

Joining an IPv4 group on a **dual** socket:

| | Linux | macOS | Windows |
|---|---|---|---|
| `MCAST_JOIN_GROUP` at `IPPROTO_IP` | yes | `EINVAL` | yes |
| `IP_ADD_MEMBERSHIP` | yes | `EINVAL` | yes |
| `IPV6_JOIN_GROUP` with `::ffff:239.255.42.99` | `EINVAL` | **yes** | `EADDRNOTAVAIL` |

IPv6 groups: `IPV6_JOIN_GROUP` (and `MCAST_JOIN_GROUP` at `IPPROTO_IPV6`) on
v6only and dual sockets, on the three. macOS needs `sa_len` set in
`group_req` (without it every `MCAST_JOIN_GROUP` is `EINVAL`), and rejects
`MCAST_JOIN_GROUP` for an IPv4 group on an IPv6 socket.

Sending to an IPv4 group **from a dual socket** (to `::ffff:a.b.c.d`):

- Linux: works; the TTL is `IP_MULTICAST_TTL`'s (`IPV6_MULTICAST_HOPS` is
  ignored: TTL seen by the receiver, `IP_RECVTTL`), the loopback is
  `IPV6_MULTICAST_LOOP`'s (`IP_MULTICAST_LOOP` is ignored), the interface
  `IP_MULTICAST_IF`'s.
- Windows: works; the IP-level options are accepted.
- macOS: **does not work**: `sendto` fails with `EHOSTUNREACH`, whatever the
  options (the IP-level ones are refused, `EINVAL`), even on `lo0`. An IPv4
  socket on the same port (`SO_REUSEADDR` + `SO_REUSEPORT`) can send for it:
  the datagrams leave from that port and reach the members. A unicast
  datagram to that port then reaches the IPv4 socket, not the dual one.

Loopback (a member on the same machine as the sender):

- Linux and macOS: `IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP` 0 **on the
  sender** stops it; on the receiver it does nothing. On Linux's `lo`
  everything comes back anyway.
- Windows: 0 **on the receiver** stops it; on the sender it does nothing.

Interfaces: the outgoing IPv4 interface by index is `IP_MULTICAST_IF` with an
`ip_mreqn` (Linux), `IP_MULTICAST_IFINDEX` (macOS), `IP_MULTICAST_IF` with
`htonl(index)` (Windows). Joining and sending on the loopback interface
works for IPv4 on the three (Linux's `lo` has no `MULTICAST` flag, but
carries IPv4 multicast); for IPv6 only on Windows. `if_nametoindex` takes
`eth0`, `en0`, and on Windows `ethernet_32773` (not the friendly name).

macOS's CI machines send no multicast out of `en0` (`EHOSTUNREACH`): there,
only `lo0` can be tested.

Sharing a port (two sockets on every address, each joining the group, both
receive):

| | Linux | macOS | Windows |
|---|---|---|---|
| `SO_REUSEADDR` | yes | second bind `EADDRINUSE` | yes |
| `SO_REUSEPORT` | yes | yes | second bind `EADDRINUSE` |
| both | yes | yes | yes |

A unicast datagram to the shared port reaches one of them only.

A socket on every address that did not join the group, on a port another
socket joined it on: Linux delivers the group's datagrams to it too
(`IP_MULTICAST_ALL`, on by default; off: nothing); macOS and Windows do not.
