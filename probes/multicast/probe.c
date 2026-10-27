/* Multicast probe: what each system accepts, and what it delivers.
 *
 * For a receiving socket of each kind (IPv4; IPv6 only; IPv6 taking IPv4
 * too, "dual", what UDPSocket opens without an address) and a group of
 * each family, tries every way of joining and says whether a datagram sent
 * to the group (loopback on, hops 1) arrives. Then: the sending options on
 * each kind of socket, two sockets sharing a port (SO_REUSEADDR,
 * SO_REUSEPORT), whether a socket gets the datagrams of a group only
 * another socket joined (Linux's IP_MULTICAST_ALL), and the interfaces.
 *
 * Usage: probe [port]                                                     */

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
        case WSAENODEV: return "ENODEV";
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

static sock_t openKind(int kind, int port, int reuse)
{
    sock_t s = socket(kind == 0 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == BAD) { printf("  socket(%s): %s\n", kindName[kind], errname(err())); return BAD; }
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
    if (rc != 0) { int e = err(); closes(s); s = BAD;
#ifdef _WIN32
        WSASetLastError(e);
#else
        errno = e;
#endif
    }
    return s;
}

static void groupAddr(int fam6, int mapped, struct sockaddr_storage *ss, socklen_type *len)
{
    memset(ss, 0, sizeof *ss);
    if (!fam6 && !mapped)
    {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET; a->sin_port = htons((unsigned short)PORT);
        inet_pton(AF_INET, G4, &a->sin_addr);
        *len = sizeof *a;
    }
    else
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6; a->sin6_port = htons((unsigned short)PORT);
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

/* method: 0 MCAST_JOIN_GROUP@IP, 1 MCAST_JOIN_GROUP@IPV6, 2 IP_ADD_MEMBERSHIP,
   3 IPV6_JOIN_GROUP (an IPv4 group as ::ffff:a.b.c.d) */
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
        if (fam6) return -2;
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
#ifndef IPV6_JOIN_GROUP
  #define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
  #define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif
        rc = setsockopt(s, IPPROTO_IPV6, leave ? IPV6_LEAVE_GROUP : IPV6_JOIN_GROUP, (const char *)&m, sizeof m);
    }
    return rc == 0 ? 0 : err();
}

/* A datagram to the group from a fresh socket of the group's family (or
   from `from`, if given); waits 500 ms on each receiver. */
static void sendTo(sock_t from, int fam6, int mapped, const char *what, unsigned ifindex)
{
    sock_t s = from;
    if (s == BAD)
    {
        s = socket(fam6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int one = 1;
        if (fam6)
        {
            setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&one, sizeof one);
            setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&one, sizeof one);
            if (ifindex) setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&ifindex, sizeof ifindex);
        }
        else
        {
#ifdef _WIN32
            DWORD l = 1, t = 1;
#else
            unsigned char l = 1, t = 1;
#endif
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&l, sizeof l);
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&t, sizeof t);
        }
    }
    struct sockaddr_storage to; socklen_type len;
    groupAddr(fam6, mapped, &to, &len);
    int n = (int)sendto(s, what, (int)strlen(what), 0, (struct sockaddr *)&to, len);
    if (n < 0) printf("    sendto: %s\n", errname(err()));
    if (from == BAD) closes(s);
}

static int received(sock_t s, int ms, char *out, size_t outLen)
{
    struct pollfd p; p.fd = s; p.events = POLLIN; p.revents = 0;
    out[0] = 0;
    if (pollsock(&p, 1, ms) <= 0) return 0;
    struct sockaddr_storage from; socklen_type fl = sizeof from;
    int n = (int)recvfrom(s, out, (int)outLen - 1, 0, (struct sockaddr *)&from, &fl);
    if (n < 0) { snprintf(out, outLen, "recv error %s", errname(err())); return 1; }
    out[n] = 0;
    return 1;
}


static unsigned mainIndex6 = 0;

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
            printf("  %-24s if4=%lu if6=%lu up=%d nomcast=%d type=%lu friendly=%ls\n",
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
            if (a->OperStatus == IfOperStatusUp && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK && !mainIndex6 && a->Ipv6IfIndex)
                mainIndex6 = a->Ipv6IfIndex;
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
        if ((a->ifa_flags & IFF_UP) && !(a->ifa_flags & IFF_LOOPBACK) && (a->ifa_flags & IFF_MULTICAST) && f == AF_INET6 && !mainIndex6)
            mainIndex6 = if_nametoindex(a->ifa_name);
    }
    freeifaddrs(list);
#endif
    printf("  main interface for IPv6 (first up, multicast, not loopback): %u\n", mainIndex6);
}

static void joins(void)
{
    printf("\n== join and deliver (sender: a fresh socket of the group's family, loop 1, hops 1)\n");
    for (int kind = 0; kind < 3; kind++)
        for (int fam6 = 0; fam6 < 2; fam6++)
            for (int method = 0; method < 4; method++)
                for (int ifi = 0; ifi < 2; ifi++)
                {
                    if (method == 2 && (fam6 || ifi)) continue;
                    unsigned idx = ifi ? mainIndex6 : 0;
                    if (ifi && idx == 0) continue;
                    sock_t r = openKind(kind, PORT, 0);
                    if (r == BAD) { printf("  %-6s bind: %s\n", kindName[kind], errname(err())); continue; }
                    int e = join(r, fam6, method, idx, 0);
                    printf("  %-6s group %-4s %-22s if=%-2u join=%-13s", kindName[kind], fam6 ? "v6" : "v4", methodName[method], idx, errname(e));
                    if (e == 0)
                    {
                        sendTo(BAD, fam6, 0, "x", idx);
                        char b[256];
                        int got = received(r, 500, b, sizeof b);
                        printf(" delivered=%s", got ? "yes" : "no");
                        int l = join(r, fam6, method, idx, 1);
                        printf(" leave=%s", errname(l));
                        if (l == 0)
                        {
                            sendTo(BAD, fam6, 0, "y", idx);
                            got = received(r, 300, b, sizeof b);
                            printf(" after-leave=%s", got ? "delivered" : "nothing");
                        }
                    }
                    printf("\n");
                    closes(r);
                }
}

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
        unsigned zero = 0;
        int rcIf6 = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&zero, sizeof zero) == 0 ? 0 : err();
        struct in_addr any; any.s_addr = htonl(INADDR_ANY);
        int rcIf4 = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&any, sizeof any) == 0 ? 0 : err();
        int v = -1; socklen_type vl = sizeof v;
        int g = getsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&v, &vl);
        printf("  %-6s IP_MULTICAST_TTL int=%s char=%s (get: %s, %d, len %d)  IP_MULTICAST_LOOP int=%s char=%s  IPV6_MULTICAST_HOPS=%s  IPV6_MULTICAST_LOOP=%s  IPV6_MULTICAST_IF=%s  IP_MULTICAST_IF=%s\n",
               kindName[kind], errname(rcTtlInt), errname(rcTtlChar), g == 0 ? "ok" : errname(err()), v, (int)vl,
               errname(rcLoopInt), errname(rcLoopChar), errname(rcHops), errname(rcLoop6), errname(rcIf6), errname(rcIf4));
        int lp = -1; vl = sizeof lp;
        g = getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&lp, &vl);
        printf("         get IPV6_MULTICAST_HOPS: %s %d\n", g == 0 ? "ok" : errname(err()), lp);
        closes(s);
    }

    printf("\n== the dual socket as sender to an IPv4 group (::ffff:a.b.c.d), receiver an IPv4 socket that joined\n");
    for (int variant = 0; variant < 4; variant++)
    {
        sock_t r = openKind(0, PORT, 0);
        join(r, 0, 2, 0, 0);
        sock_t s = openKind(2, 0, 0);
        int one = 1, zero = 0;
        const char *what = "";
        if (variant == 0) what = "defaults";
        if (variant == 1) { what = "IP_MULTICAST_LOOP 0"; setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&zero, sizeof zero); }
        if (variant == 2) { what = "IPV6_MULTICAST_LOOP 0"; setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&zero, sizeof zero); }
        if (variant == 3) { what = "both LOOP 0"; setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&zero, sizeof zero);
                                                  setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&zero, sizeof zero); }
        (void)one;
        sendTo(s, 0, 1, "m", 0);
        char b[256];
        int got = received(r, 500, b, sizeof b);
        printf("  %-22s delivered=%s\n", what, got ? "yes" : "no");
        closes(s); closes(r);
    }

    printf("\n== loop off on the sender, receiver on the same host (Windows applies IP_MULTICAST_LOOP on the receiving side?)\n");
    for (int fam6 = 0; fam6 < 2; fam6++)
        for (int where = 0; where < 2; where++)
        {
            sock_t r = openKind(fam6 ? 1 : 0, PORT, 0);
            join(r, fam6, fam6 ? 3 : 2, 0, 0);
            sock_t s = socket(fam6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            int zero = 0;
            sock_t target = where ? r : s;
            int rc = fam6 ? setsockopt(target, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&zero, sizeof zero)
                          : setsockopt(target, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&zero, sizeof zero);
            sendTo(s, fam6, 0, "l", 0);
            char b[256];
            int got = received(r, 500, b, sizeof b);
            printf("  %s loop 0 on the %s (%s): delivered=%s\n", fam6 ? "v6" : "v4", where ? "receiver" : "sender",
                   rc == 0 ? "ok" : errname(err()), got ? "yes" : "no");
            closes(s); closes(r);
        }
}

static void sharing(void)
{
    printf("\n== two receivers on one port (each joins the group), both IPv4 / both dual\n");
    for (int kind = 0; kind < 3; kind += 2)
        for (int reuse = 1; reuse <= 3; reuse++)
        {
            sock_t a = openKind(kind, PORT, reuse);
            int ea = a == BAD ? err() : 0;
            sock_t b = openKind(kind, PORT, reuse);
            int eb = b == BAD ? err() : 0;
            printf("  %-6s %-22s first=%s second=%s", kindName[kind],
                   reuse == 1 ? "SO_REUSEADDR" : reuse == 2 ? "SO_REUSEPORT" : "SO_REUSEADDR+PORT", errname(ea), errname(eb));
            if (a != BAD && b != BAD)
            {
                int m = kind == 0 ? 2 : 1;
                join(a, 0, m, 0, 0); join(b, 0, m, 0, 0);
                sendTo(BAD, 0, 0, "s", 0);
                char x[256];
                int ga = received(a, 500, x, sizeof x), gb = received(b, 500, x, sizeof x);
                printf(" multicast to both: %s/%s", ga ? "yes" : "no", gb ? "yes" : "no");
                /* unicast to the port: who gets it? */
                sock_t u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                struct sockaddr_in to; memset(&to, 0, sizeof to);
                to.sin_family = AF_INET; to.sin_port = htons((unsigned short)PORT); to.sin_addr.s_addr = htonl(0x7f000001);
                sendto(u, "u", 1, 0, (struct sockaddr *)&to, sizeof to);
                closes(u);
                ga = received(a, 300, x, sizeof x); gb = received(b, 300, x, sizeof x);
                printf("  unicast: %s/%s", ga ? "yes" : "no", gb ? "yes" : "no");
            }
            printf("\n");
            if (a != BAD) closes(a);
            if (b != BAD) closes(b);
        }

    printf("\n== a socket that joined nothing, sharing the port with one that joined (IP_MULTICAST_ALL)\n");
    for (int kind = 0; kind < 3; kind += 2)
        for (int all = 0; all < 2; all++)
        {
            sock_t a = openKind(kind, PORT, 3), b = openKind(kind, PORT, 3);
            if (a == BAD || b == BAD) { printf("  bind failed\n"); continue; }
            const char *note = "default";
#ifdef IP_MULTICAST_ALL
            if (all) { int zero = 0; int rc = setsockopt(a, IPPROTO_IP, IP_MULTICAST_ALL, (const char *)&zero, sizeof zero);
                       note = rc == 0 ? "IP_MULTICAST_ALL 0" : "IP_MULTICAST_ALL 0 refused"; }
#else
            if (all) { closes(a); closes(b); continue; }
#endif
            join(b, 0, kind == 0 ? 2 : 1, 0, 0);
            sendTo(BAD, 0, 0, "a", 0);
            char x[256];
            int ga = received(a, 500, x, sizeof x), gb = received(b, 500, x, sizeof x);
            printf("  %-6s %-26s not joined: %s, joined: %s\n", kindName[kind], note, ga ? "GOT IT" : "nothing", gb ? "yes" : "no");
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
