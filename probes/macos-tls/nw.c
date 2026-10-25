/* Network.framework: it makes its own connection (nw_connection); there is
   no call to hand it a socket we opened. Usage: nw host [port] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Network/Network.h>
#include <dispatch/dispatch.h>

int main(int argc, char **argv)
{
    const char *host = argv[1], *port = argc > 2 ? argv[2] : "443";
    printf("Network.framework -> %s:%s\n", host, port);
    nw_endpoint_t ep = nw_endpoint_create_host(host, port);
    nw_parameters_t params = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DEFAULT_CONFIGURATION, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_connection_t conn = nw_connection_create(ep, params);
    dispatch_queue_t q = dispatch_queue_create("probe", NULL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int ok = 0;
    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t err) {
        if (state == nw_connection_state_ready) { ok = 1; dispatch_semaphore_signal(done); }
        else if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
            if (err) printf("  error: domain %d, code %d\n", (int)nw_error_get_error_domain(err), nw_error_get_error_code(err));
            dispatch_semaphore_signal(done);
        }
    });
    nw_connection_set_queue(conn, q);
    nw_connection_start(conn);
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 20LL * NSEC_PER_SEC)) != 0) {
        printf("  RESULT: no answer in 20 s\n"); return 0;
    }
    if (!ok) { printf("  RESULT: failed\n"); nw_connection_cancel(conn); return 0; }
    nw_protocol_metadata_t md = nw_connection_copy_protocol_metadata(conn, nw_protocol_copy_tls_definition());
    sec_protocol_metadata_t smd = nw_tls_copy_sec_protocol_metadata(md);
    tls_protocol_version_t v = sec_protocol_metadata_get_negotiated_tls_protocol_version(smd);
    char req[256]; snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    dispatch_data_t d = dispatch_data_create(req, strlen(req), q, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t e) { (void)e; });
    char *line = calloc(128, 1);
    nw_connection_receive(conn, 1, 128, ^(dispatch_data_t content, nw_content_context_t c, bool complete, nw_error_t e) {
        (void)c; (void)complete; (void)e;
        if (content) dispatch_data_apply(content, ^bool(dispatch_data_t r, size_t off, const void *buf, size_t size) {
            (void)r; size_t n = size < 127 - off ? size : 127 - off; memcpy(line + off, buf, n); return true; });
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 20LL * NSEC_PER_SEC));
    char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
    printf("  RESULT: OK, %s, first line: %s\n",
           v == tls_protocol_version_TLSv13 ? "TLS 1.3" : v == tls_protocol_version_TLSv12 ? "TLS 1.2" : "other", line);
    nw_connection_cancel(conn);
    return 0;
}
