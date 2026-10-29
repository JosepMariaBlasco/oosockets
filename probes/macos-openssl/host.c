/* Loads the probe's library as ooRexx loads liboosockets (dlopen), calls
   plain code, then asks for TLS.   host <path to libprobe.dylib>         */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("  dlopen FAILED: %s\n", dlerror()); return 1; }
    int (*plain)(char *, int) = (int (*)(char *, int))dlsym(h, "probe_plain");
    int (*tls)(char *, int) = (int (*)(char *, int))dlsym(h, "probe_tls");
    char buf[1024];
    plain(buf, sizeof buf); printf("  loaded; %s\n", buf);
    int ok = tls(buf, sizeof buf); printf("  %s\n", buf);
    return ok ? 0 : 3;
}
