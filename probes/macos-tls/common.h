/* Shared by the macOS TLS probes: a plain TCP connection, as Socket makes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *list, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0) { printf("  getaddrinfo: %s\n", gai_strerror(rc)); return -1; }
    int fd = -1;
    for (ai = list; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(list);
    if (fd < 0) printf("  connect failed: %s\n", strerror(errno));
    int one = 1; if (fd >= 0) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    return fd;
}
