/* Multicast probe: what each system accepts, and what it delivers.
 *
 * For a receiving socket of each kind (IPv4; IPv6 only; IPv6 taking IPv4
 * too, "dual", what UDPSocket opens without an address), a group of each
 * family and an interface (none: the system's choice; the main one; the
 * loopback), tries every way of joining and says whether a datagram sent
 * to the group (loopback on, hops 1, out of that interface) arrives. Then:
 * the sending options on each kind of socket and which one a dual socket
 * obeys for an IPv4 group (the TTL seen by the receiver), two sockets
 * sharing a port, whether a socket gets the datagrams of a group only
 * another socket joined (Linux's IP_MULTICAST_ALL), and the interfaces.
 *
 * Usage: probe [port]                                                     */

#define __APPLE_USE_RFC_3542 1     /* macOS: IPV6_HOPLIMIT */
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <windows.h>
  typedef SOCKET sock_t;
  typedef int socklen_type;
  #define BAD INVALID_SOCKET
  #define closes closesocket
  #define err() WSAGetLastError()
  #define pollsock WSAPoll
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/uio.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <net/if.h>
  #include <ifaddrs.h>
  #include <netdb.h>
  #include <poll.h>
  #include <unistd.h>
  #include <errno.h>
  typedef int sock_t;
  typedef socklen_t socklen_type;
  #define BAD (-1)
  #define closes close
  #define err() errno
  #define pollsock poll
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
  #define HAS_SA_LEN 1
#endif
#ifndef IPV6_JOIN_GROUP
  #define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
  #define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif

static int PORT = 47000;
static const char *G4 = "239.255.42.99";
static const char *G6 = "ff12::4299";     /* transient, link-local scope */

static const char *kindName[] = {"v4", "v6only", "dual"};

static const char *errname(int e)
{
    static char buf[32];
#ifdef _WIN32
    switch (e)
    {
        case 0: return "ok";
        case WSAEINVAL: return "EINVAL";
        case WSAENOPROTOOPT: return "ENOPROTOOPT";
        case WSAEADDRNOTAVAIL: return "EADDRNOTAVAIL";
        case WSAEADDRINUSE: return "EADDRINUSE";
        case WSAEAFNOSUPPORT: return "EAFNOSUPPORT";
        case WSAENETUNREACH: return "ENETUNREACH";
        case WSAEHOSTUNREACH: return "EHOSTUNREACH";
        case WSAEACCES: return "EACCES";
        case WSAEFAULT: return "EFAULT";
    }
#else
    switch (e)
    {
        case 0: return "ok";
        case EINVAL: return "EINVAL";
        case ENOPROTOOPT: return "ENOPROTOOPT";
        case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
        case EADDRINUSE: return "EADDRINUSE";
        case EAFNOSUPPORT: return "EAFNOSUPPORT";
        case ENETUNREACH: return "ENETUNREACH";
        case EHOSTUNREACH: return "EHOSTUNREACH";
        case EACCES: return "EACCES";
        case EFAULT: return "EFAULT";
        case ENODEV: return "ENODEV";
        case ENXIO: return "ENXIO";
        case EOPNOTSUPP: return "EOPNOTSUPP";
    }
#endif
    snprintf(buf, sizeof buf, "err%d", e);
    return buf;
}

static void setErr(int e)
{
#ifdef _WIN32
    WSASetLastError(e);
#else
    errno = e;
#endif
}

/* reuse: 1 SO_REUSEADDR, 2 SO_REUSEPORT */
static sock_t openKind(int kind, int port, int reuse)
{
    sock_t s = socket(kind == 0 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == BAD) return BAD;
    int one = 1, zero = 0;
    if (kind > 0)
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)(kind == 1 ? &one : &zero), sizeof(int));
    if (reuse & 1) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
#ifdef SO_REUSEPORT
    if (reuse & 2) setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof one);
#endif
    int rc;
    if (kind == 0)
    {
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = htonl(INADDR_ANY);
        rc = bind(s, (struct sockaddr *)&a, sizeof a);
    }
    else
    {
        struct sockaddr_in6 a; memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6; a.sin6_port = htons((unsigned short)port); a.sin6_addr = in6addr_any;
        rc = bind(s, (struct sockaddr *)&a, sizeof a);
    }
    if (rc != 0) { int e = err(); closes(s); setErr(e); return BAD; }
    return s;
}

static void groupAddr(int fam6, int mapped, struct sockaddr_storage *ss, socklen_type *len)
{
    memset(ss, 0, sizeof *ss);
    if (!fam6 && !mapped)
    {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET; a->sin_port = htons((unsigned short)PORT);
#ifdef HAS_SA_LEN
        a->sin_len = sizeof *a;
#endif
        inet_pton(AF_INET, G4, &a->sin_addr);
        *len = sizeof *a;
    }
    else
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6; a->sin6_port = htons((unsigned short)PORT);
#ifdef HAS_SA_LEN
        a->sin6_len = sizeof *a;
#endif
        if (fam6) inet_pton(AF_INET6, G6, &a->sin6_addr);
        else
        {
            unsigned char *b = (unsigned char *)&a->sin6_addr;
            b[10] = 0xff; b[11] = 0xff;
            inet_pton(AF_INET, G4, b + 12);
        }
        *len = sizeof *a;
    }
}

/* method: 0 MCAST_JOIN_GROUP@IP, 1 MCAST_JOIN_GROUP@IPV6, 2 IP_ADD_MEMBERSHIP
   (interface 0 only), 3 IPV6_JOIN_GROUP (an IPv4 group as ::ffff:a.b.c.d) */
static const char *methodName[] = {"MCAST_JOIN_GROUP@IP", "MCAST_JOIN_GROUP@IPV6", "IP_ADD_MEMBERSHIP", "IPV6_JOIN_GROUP"};

static int join(sock_t s, int fam6, int method, unsigned ifindex, int leave)
{
    int rc;
    if (method <= 1)
    {
        struct group_req r; memset(&r, 0, sizeof r);
        r.gr_interface = ifindex;
        socklen_type len;
        groupAddr(fam6, 0, &r.gr_group, &len);
        rc = setsockopt(s, method == 0 ? IPPROTO_IP : IPPROTO_IPV6,
                        leave ? MCAST_LEAVE_GROUP : MCAST_JOIN_GROUP, (const char *)&r, sizeof r);
    }
    else if (method == 2)
    {
        if (fam6 || ifindex) return -2;
        struct ip_mreq m; memset(&m, 0, sizeof m);
        inet_pton(AF_INET, G4, &m.imr_multiaddr);
        m.imr_interface.s_addr = htonl(INADDR_ANY);
        rc = setsockopt(s, IPPROTO_IP, leave ? IP_DROP_MEMBERSHIP : IP_ADD_MEMBERSHIP, (const char *)&m, sizeof m);
    }
    else
    {
        struct ipv6_mreq m; memset(&m, 0, sizeof m);
        struct sockaddr_storage ss; socklen_type len;
        groupAddr(fam6, !fam6, &ss, &len);
        m.ipv6mr_multiaddr = ((struct sockaddr_in6 *)&ss)->sin6_addr;
        m.ipv6mr_interface = ifindex;
        rc = setsockopt(s, IPPROTO_IPV6, leave ? IPV6_LEAVE_GROUP : IPV6_JOIN_GROUP, (const char *)&m, sizeof m);
    }
    return rc == 0 ? 0 : err();
}

/* The first method that joins; -1 if none. */
static int joinAny(sock_t s, int fam6, unsigned ifindex)
{
    for (int m = 0; m < 4; m++)
        if (join(s, fam6, m, ifindex, 0) == 0) return m;
    return -1;
}

/* The IPv4 outgoing interface by index: 0 ok, else the error. */
static int setIf4(sock_t s, unsigned idx)
{
#if defined(_WIN32)
    DWORD v = htonl(idx);            /* "0.0.0.idx": an index, not an address */
    return setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&v, sizeof v) == 0 ? 0 : err();
#elif defined(__APPLE__)
    unsigned v = idx;
    return setsockopt(s, IPPROTO_IP, IP_MULTICAST_IFINDEX, (const char *)&v, sizeof v) == 0 ? 0 : err();
#else
    struct ip_mreqn m; memset(&m, 0, sizeof m);
    m.imr_ifindex = (int)idx;
    return setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&m, sizeof m) == 0 ? 0 : err();
#endif
}

static int setIf6(sock_t s, unsigned idx)
{
    return setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&idx, sizeof idx) == 0 ? 0 : err();
}

/* A datagram to the group from a fresh socket of the group's family, loop
   1, hops 1, out of ifindex (if not 0). */
static void sendFresh(int fam6, const char *what, unsigned ifindex)
{
    sock_t s = socket(fam6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int one = 1;
    if (fam6)
    {
        setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&one, sizeof one);
        setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&one, sizeof one);
        if (ifindex) { int e = setIf6(s, ifindex); if (e) printf(" [IPV6_MULTICAST_IF %s]", errname(e)); }
    }
    else
    {
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&one, sizeof one);
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&one, sizeof one);
        if (ifindex) { int e = setIf4(s, ifindex); if (e) printf(" [IP_MULTICAST_IF %s]", errname(e)); }
    }
    struct sockaddr_storage to; socklen_type len;
    groupAddr(fam6, 0, &to, &len);
    if (fam6) ((struct sockaddr_in6 *)&to)->sin6_scope_id = ifindex;   /* ff12:: is link-local */
    int n = (int)sendto(s, what, (int)strlen(what), 0, (struct sockaddr *)&to, len);
    if (n < 0) printf(" [sendto %s]", errname(err()));
    closes(s);
}

static int received(sock_t s, int ms)
{
    struct pollfd p; p.fd = s; p.events = POLLIN; p.revents = 0;
    if (pollsock(&p, 1, ms) <= 0) return 0;
    char out[512];
    struct sockaddr_storage from; socklen_type fl = sizeof from;
    int n = (int)recvfrom(s, out, (int)sizeof out, 0, (struct sockaddr *)&from, &fl);
    return n >= 0 ? 1 : 0;
}

static unsigned mainIf = 0, loopIf = 0;

static void interfaces(void)
{
    printf("== interfaces\n");
#ifdef _WIN32
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    IP_ADAPTER_ADDRESSES *aa = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, aa, &size) == 0)
    {
        for (IP_ADAPTER_ADDRESSES *a = aa; a; a = a->Next)
        {
            printf("  %s if4=%lu if6=%lu up=%d nomcast=%d type=%lu friendly=%ls\n",
                   a->AdapterName, a->IfIndex, a->Ipv6IfIndex, a->OperStatus == IfOperStatusUp,
                   (a->Flags & IP_ADAPTER_NO_MULTICAST) != 0, a->IfType, a->FriendlyName);
            char nm[IF_NAMESIZE + 1] = "";
            if (if_indextoname(a->IfIndex, nm)) printf("    if_indextoname(%lu) = %s; if_nametoindex = %lu\n", a->IfIndex, nm, if_nametoindex(nm));
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next)
            {
                char h[INET6_ADDRSTRLEN] = "";
                getnameinfo(u->Address.lpSockaddr, u->Address.iSockaddrLength, h, sizeof h, NULL, 0, NI_NUMERICHOST);
                printf("    %s\n", h);
            }
            if (a->OperStatus == IfOperStatusUp && a->IfType == IF_TYPE_SOFTWARE_LOOPBACK && !loopIf) loopIf = a->IfIndex;
            if (a->OperStatus == IfOperStatusUp && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK && !mainIf
                && a->IfIndex == a->Ipv6IfIndex && !(a->Flags & IP_ADAPTER_NO_MULTICAST))
                mainIf = a->IfIndex;
        }
    }
    free(aa);
#else
    struct ifaddrs *list = NULL;
    getifaddrs(&list);
    for (struct ifaddrs *a = list; a; a = a->ifa_next)
    {
        if (!a->ifa_addr) continue;
        int f = a->ifa_addr->sa_family;
        if (f != AF_INET && f != AF_INET6) continue;
        char h[INET6_ADDRSTRLEN + 20] = "";
        getnameinfo(a->ifa_addr, f == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), h, sizeof h, NULL, 0, NI_NUMERICHOST);
        printf("  %-8s index=%u up=%d loopback=%d multicast=%d %s\n", a->ifa_name, if_nametoindex(a->ifa_name),
               (a->ifa_flags & IFF_UP) != 0, (a->ifa_flags & IFF_LOOPBACK) != 0, (a->ifa_flags & IFF_MULTICAST) != 0, h);
        if ((a->ifa_flags & IFF_UP) && (a->ifa_flags & IFF_LOOPBACK) && !loopIf) loopIf = if_nametoindex(a->ifa_name);
        if ((a->ifa_flags & IFF_UP) && !(a->ifa_flags & IFF_LOOPBACK) && (a->ifa_flags & IFF_MULTICAST) && f == AF_INET && !mainIf)
            mainIf = if_nametoindex(a->ifa_name);
    }
    freeifaddrs(list);
#endif
    printf("  main interface (first up, multicast, IPv4, not loopback): %u; loopback: %u\n", mainIf, loopIf);
}

static void joins(void)
{
    printf("\n== join and deliver (sender: a fresh socket of the group's family, loop 1, hops 1, out of the interface)\n");
    unsigned ifs[3] = {0, mainIf, loopIf};
    for (int kind = 0; kind < 3; kind++)
        for (int fam6 = 0; fam6 < 2; fam6++)
            for (int i = 0; i < 3; i++)
                for (int method = 0; method < 4; method++)
                {
                    unsigned idx = ifs[i];
                    if (i > 0 && idx == 0) continue;
                    if (method == 2 && (fam6 || idx)) continue;
                    sock_t r = openKind(kind, PORT, 0);
                    if (r == BAD) { printf("  %-6s bind: %s\n", kindName[kind], errname(err())); continue; }
                    int e = join(r, fam6, method, idx, 0);
                    printf("  %-6s group %s if=%-2u %-22s join=%-13s", kindName[kind], fam6 ? "v6" : "v4", idx, methodName[method], errname(e));
                    if (e == 0)
                    {
                        sendFresh(fam6, "x", idx);
                        int got = received(r, 400);
                        printf(" delivered=%s", got ? "yes" : "no");
                        int l = join(r, fam6, method, idx, 1);
                        printf(" leave=%s", errname(l));
                        if (l == 0 && got)
                        {
                            sendFresh(fam6, "y", idx);
                            printf(" after-leave=%s", received(r, 300) ? "DELIVERED" : "nothing");
                        }
                    }
                    printf("\n");
                    closes(r);
                }
}

#ifndef _WIN32
/* Receives one datagram and its TTL / hop limit; -1 if none, -2 if no TTL. */
static int receivedTtl(sock_t s, int ms)
{
    struct pollfd p; p.fd = s; p.events = POLLIN; p.revents = 0;
    if (poll(&p, 1, ms) <= 0) return -1;
    char data[512], ctl[512];
    struct iovec iov; iov.iov_base = data; iov.iov_len = sizeof data;
    struct msghdr m; memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = ctl; m.msg_controllen = sizeof ctl;
    if (recvmsg(s, &m, 0) < 0) return -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
    {
        if (c->cmsg_level == IPPROTO_IP && (c->cmsg_type == IP_TTL || c->cmsg_type == IP_RECVTTL))
        {
            if (c->cmsg_len >= CMSG_LEN(sizeof(int))) return *(int *)CMSG_DATA(c);
            return *(unsigned char *)CMSG_DATA(c);
        }
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT) return *(int *)CMSG_DATA(c);
    }
    return -2;
}
#endif

static void sendOptions(void)
{
    printf("\n== sending options on each kind of socket\n");
    for (int kind = 0; kind < 3; kind++)
    {
        sock_t s = openKind(kind, 0, 0);
        if (s == BAD) continue;
        int one = 1, three = 3;
        unsigned char c3 = 3, c1 = 1;
        int rcTtlInt = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&three, sizeof three) == 0 ? 0 : err();
        int rcTtlChar = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&c3, sizeof c3) == 0 ? 0 : err();
        int rcLoopInt = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&one, sizeof one) == 0 ? 0 : err();
        int rcLoopChar = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&c1, sizeof c1) == 0 ? 0 : err();
        int rcHops = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&three, sizeof three) == 0 ? 0 : err();
        int rcLoop6 = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&one, sizeof one) == 0 ? 0 : err();
        int rcIf6 = mainIf ? setIf6(s, mainIf) : -3;
        int rcIf4 = mainIf ? setIf4(s, mainIf) : -3;
        int v = -1; socklen_type vl = sizeof v;
        int g = getsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&v, &vl);
        printf("  %-6s IP_MULTICAST_TTL int=%s char=%s (get %s %d len %d)  IP_MULTICAST_LOOP int=%s char=%s\n"
               "         IPV6_MULTICAST_HOPS=%s IPV6_MULTICAST_LOOP=%s  IPV6_MULTICAST_IF(main)=%s IP_MULTICAST_IF(main, by index)=%s\n",
               kindName[kind], errname(rcTtlInt), errname(rcTtlChar), g == 0 ? "ok" : errname(err()), v, (int)vl,
               errname(rcLoopInt), errname(rcLoopChar), errname(rcHops), errname(rcLoop6), errname(rcIf6), errname(rcIf4));
        int lp = -1; vl = sizeof lp;
        g = getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&lp, &vl);
        int dl = -1; socklen_type dll = sizeof dl;
        int g2 = getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&dl, &dll);
        printf("         get IPV6_MULTICAST_HOPS: %s %d; IPV6_MULTICAST_LOOP default: %s %d\n", g == 0 ? "ok" : errname(err()), lp,
               g2 == 0 ? "ok" : "err", dl);
        closes(s);
    }

    for (int ii = 0; ii < 2; ii++)
    {
        unsigned I = ii ? loopIf : mainIf;
        if (I == 0) continue;
        printf("\n== a dual socket sending to an IPv4 group (::ffff:a.b.c.d); receiver: an IPv4 socket that joined (interface %u)\n", I);
        for (int variant = 0; variant < 7; variant++)
        {
            sock_t r = openKind(0, PORT, 0);
            int jm = joinAny(r, 0, I);
    #ifndef _WIN32
            int on = 1;
            setsockopt(r, IPPROTO_IP, IP_RECVTTL, (const char *)&on, sizeof on);
    #endif
            sock_t s = openKind(2, 0, 0);
            int zero = 0, five = 5, seven = 7;
            const char *what = "";
            int e1 = 0, e2 = 0;
            if (I) { setIf6(s, I); if (variant != 6) setIf4(s, I); }
            if (variant == 0) what = "defaults";
            if (variant == 6) what = "only IPV6_MULTICAST_IF";
            if (variant == 1) { what = "IP_MULTICAST_LOOP 0"; e1 = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&zero, sizeof zero); }
            if (variant == 2) { what = "IPV6_MULTICAST_LOOP 0"; e1 = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&zero, sizeof zero); }
            if (variant == 3) { what = "IP_MULTICAST_TTL 5"; e1 = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&five, sizeof five); }
            if (variant == 4) { what = "IPV6_MULTICAST_HOPS 7"; e1 = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&seven, sizeof seven); }
            if (variant == 5) { what = "TTL 5 and HOPS 7"; e1 = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&five, sizeof five);
                                                           e2 = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&seven, sizeof seven); }
            struct sockaddr_storage to; socklen_type len;
            groupAddr(0, 1, &to, &len);
            int n = (int)sendto(s, "m", 1, 0, (struct sockaddr *)&to, len);
            int se = n < 0 ? err() : 0;
    #ifndef _WIN32
            int ttl = receivedTtl(r, 400);
            printf("  %-22s (set %s %s; join %d; send %s) delivered=%s ttl=%d\n", what, e1 ? "FAIL" : "ok", e2 ? "FAIL" : "ok", jm,
                   errname(se), ttl >= -2 && ttl != -1 ? "yes" : "no", ttl);
    #else
            printf("  %-22s (set %s %s; join %d; send %s) delivered=%s\n", what, e1 ? "FAIL" : "ok", e2 ? "FAIL" : "ok", jm,
                   errname(se), received(r, 400) ? "yes" : "no");
    #endif
            closes(s); closes(r);
        }

        printf("\n== loop 0 set on the sender, or on the receiver (same host, interface %u)\n", I);
        for (int fam6 = 0; fam6 < 2; fam6++)
            for (int where = 0; where < 2; where++)
            {
                sock_t r = openKind(fam6 ? 1 : 0, PORT, 0);
                joinAny(r, fam6, I);
                sock_t s = socket(fam6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (I) { if (fam6) setIf6(s, I); else setIf4(s, I); }
                int zero = 0;
                sock_t target = where ? r : s;
                int rc = fam6 ? setsockopt(target, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&zero, sizeof zero)
                              : setsockopt(target, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&zero, sizeof zero);
                struct sockaddr_storage to; socklen_type len;
                groupAddr(fam6, 0, &to, &len);
                sendto(s, "l", 1, 0, (struct sockaddr *)&to, len);
                printf("  %s loop 0 on the %s (%s): delivered=%s\n", fam6 ? "v6" : "v4", where ? "receiver" : "sender  ",
                       rc == 0 ? "ok" : errname(err()), received(r, 400) ? "yes" : "no");
                closes(s); closes(r);
            }
    }
}

static void sharing(void)
{
    printf("\n== two receivers on one port, each joins the IPv4 group (interface %u)\n", mainIf);
    for (int kind = 0; kind < 3; kind += 2)
        for (int reuse = 1; reuse <= 3; reuse++)
        {
            sock_t a = openKind(kind, PORT, reuse);
            int ea = a == BAD ? err() : 0;
            sock_t b = openKind(kind, PORT, reuse);
            int eb = b == BAD ? err() : 0;
            printf("  %-6s %-18s first=%s second=%s", kindName[kind],
                   reuse == 1 ? "SO_REUSEADDR" : reuse == 2 ? "SO_REUSEPORT" : "SO_REUSEADDR+PORT", errname(ea), errname(eb));
            if (a != BAD && b != BAD)
            {
                int ja = joinAny(a, 0, mainIf), jb = joinAny(b, 0, mainIf);
                sendFresh(0, "s", mainIf);
                int ga = received(a, 400), gb = received(b, 400);
                printf(" joins %d/%d multicast to both: %s/%s", ja, jb, ga ? "yes" : "no", gb ? "yes" : "no");
                sock_t u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                struct sockaddr_in to; memset(&to, 0, sizeof to);
                to.sin_family = AF_INET; to.sin_port = htons((unsigned short)PORT); to.sin_addr.s_addr = htonl(0x7f000001);
                sendto(u, "u", 1, 0, (struct sockaddr *)&to, sizeof to);
                closes(u);
                ga = received(a, 300); gb = received(b, 300);
                printf("  unicast: %s/%s", ga ? "yes" : "no", gb ? "yes" : "no");
            }
            printf("\n");
            if (a != BAD) closes(a);
            if (b != BAD) closes(b);
        }

    printf("\n== a socket that joined nothing, sharing the port with one that joined\n");
    for (int kind = 0; kind < 3; kind += 2)
        for (int all = 0; all < 2; all++)
        {
            sock_t a = openKind(kind, PORT, 3), b = openKind(kind, PORT, 3);
            if (a == BAD || b == BAD) { printf("  bind failed\n"); if (a != BAD) closes(a); if (b != BAD) closes(b); continue; }
            const char *note = "default";
#ifdef IP_MULTICAST_ALL
            if (all)
            {
                int zero = 0;
                int rc = setsockopt(a, IPPROTO_IP, IP_MULTICAST_ALL, (const char *)&zero, sizeof zero);
  #ifdef IPV6_MULTICAST_ALL
                if (kind) rc |= setsockopt(a, IPPROTO_IPV6, IPV6_MULTICAST_ALL, (const char *)&zero, sizeof zero);
  #endif
                note = rc == 0 ? "IP(V6)_MULTICAST_ALL 0" : "MULTICAST_ALL 0 refused";
            }
#else
            if (all) { closes(a); closes(b); continue; }
#endif
            int jb = joinAny(b, 0, mainIf);
            sendFresh(0, "a", mainIf);
            int ga = received(a, 400), gb = received(b, 400);
            printf("  %-6s %-24s join %d; not joined: %s, joined: %s\n", kindName[kind], note, jb, ga ? "GOT IT" : "nothing", gb ? "yes" : "no");
            closes(a); closes(b);
        }
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
#endif
    if (argc > 1) PORT = atoi(argv[1]);
    setvbuf(stdout, NULL, _IONBF, 0);
    interfaces();
    joins();
    sendOptions();
    sharing();
    printf("\ndone\n");
    return 0;
}
