/*
 * Make uname() agree with the machine we claim to be.
 *
 * A container shares the host's kernel, so uname() returns the host's release
 * string. On a Docker Desktop host that is literally:
 *
 *     $ uname -r
 *     6.6.87.2-microsoft-standard-WSL2
 *
 * while our motd claims 5.15.0-118-generic. That is a self-contradiction an
 * attacker finds in one command, and "microsoft-standard-WSL2" additionally
 * announces the whole hosting arrangement. It was the single loudest tell
 * left on the node.
 *
 * The kernel will not lie for us and we hold no capability to make it, so we
 * intercept the call instead: this is loaded through /etc/ld.so.preload, wraps
 * glibc's uname(), and rewrites `release` and `version` in the result. That
 * covers `uname -a`, `uname -r`, and every tool and language runtime that asks
 * the same way.
 *
 * Compiled in a builder stage so no compiler ships in the final image.
 *
 * Known residual: /proc/version and /proc/sys/kernel/osrelease are read
 * straight from procfs and are not affected. Masking those needs a mount the
 * container cannot perform on itself, so it belongs to the host-side hardening
 * in phase 3. Tracked in the pre-launch checklist.
 *
 * Care is required here. /etc/ld.so.preload applies to every dynamically
 * linked process on the system: if this library fails to load, the loader
 * prints a warning before *every* command an attacker runs, which is far worse
 * than the problem it solves. Keep it dependency-free, and keep the fallback
 * path silent.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <string.h>
#include <sys/utsname.h>

#ifndef FAKE_RELEASE
#define FAKE_RELEASE "5.15.0-118-generic"
#endif

#ifndef FAKE_VERSION
#define FAKE_VERSION "#128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2026"
#endif

static void copy_field(char *dst, const char *src, size_t size)
{
    if (size == 0) {
        return;
    }
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

int uname(struct utsname *buf)
{
    static int (*real_uname)(struct utsname *) = NULL;

    if (real_uname == NULL) {
        real_uname = (int (*)(struct utsname *))dlsym(RTLD_NEXT, "uname");
        if (real_uname == NULL) {
            /* Nothing sensible to fall back to. Report failure quietly
             * rather than writing to stderr on every process start. */
            return -1;
        }
    }

    int rc = real_uname(buf);
    if (rc == 0) {
        copy_field(buf->release, FAKE_RELEASE, sizeof(buf->release));
        copy_field(buf->version, FAKE_VERSION, sizeof(buf->version));
    }
    return rc;
}
