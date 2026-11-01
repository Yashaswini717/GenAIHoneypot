/*
 * Make the node's kernel and its uptime agree with the machine we claim to be.
 *
 * Two interceptions, both for the same reason: the kernel is the host's and it
 * will not lie for us, and we hold no capability to make it.
 *
 * 1. uname()
 * ----------
 * A container shares the host's kernel, so uname() returns the host's release
 * string. On a Docker Desktop host that is literally:
 *
 *     $ uname -r
 *     6.6.87.2-microsoft-standard-WSL2
 *
 * while our motd claims 5.15.0-118-generic. That is a self-contradiction an
 * attacker finds in one command, and "microsoft-standard-WSL2" additionally
 * announces the whole hosting arrangement.
 *
 * 2. /proc/uptime
 * ---------------
 * procfs reports the *host's* uptime, which has nothing to do with this
 * container. Once the boot script started logging properly, syslog carried a
 * genuine boot sequence timestamped at container start while `uptime` claimed
 * five and a half hours -- "syslog says you booted ninety seconds ago, uptime
 * says five hours", one command each.
 *
 * What we report instead is the container's own uptime, which is the truth and
 * is also the only internally consistent answer available. Claiming the long
 * uptime the seeded history implies would contradict something more visible
 * than /proc/uptime: `ps` derives every process's start time from btime, so a
 * box claiming ninety-four days would show sshd, cron and rsyslogd starting
 * today. Short and consistent beats long and contradicted.
 *
 * The container's boot time is derived, not configured: btime from /proc/stat
 * is the host's boot, and field 22 of /proc/1/stat is PID 1's start in clock
 * ticks since then. PID 1 is this container's init, so their sum is when this
 * container started. Nothing has to be baked in at build time and there is no
 * file on the box holding the answer.
 *
 * btime itself is deliberately left alone. Shifting it would move every
 * process's apparent start time with it, and `ps aux` is a far more common
 * command than `grep btime /proc/stat`. That leaves btime implying the host's
 * uptime -- a residual, and a much deeper check than the one this removes.
 *
 * Compiled in a builder stage so no compiler ships in the final image.
 *
 * Known residual: /proc/version and /proc/sys/kernel/osrelease are read
 * straight from procfs. Masking those needs a mount the container cannot
 * perform on itself, so it belongs to host-side hardening. Tracked in the
 * pre-launch checklist.
 *
 * Care is required here. /etc/ld.so.preload applies to every dynamically
 * linked process on the system: if this library fails to load, the loader
 * prints a warning before *every* command an attacker runs, which is far worse
 * than the problems it solves. Keep it dependency-free, and keep every
 * fallback path silent and passing through to the real function.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef FAKE_RELEASE
#define FAKE_RELEASE "5.15.0-118-generic"
#endif

#ifndef FAKE_VERSION
#define FAKE_VERSION "#128-Ubuntu SMP Fri Jul 5 09:28:59 UTC 2026"
#endif

#define UPTIME_PATH "/proc/uptime"

static void copy_field(char *dst, const char *src, size_t size)
{
    if (size == 0) {
        return;
    }
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

/* ------------------------------------------------------------------------- *
 * uname
 * ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- *
 * /proc/uptime
 * ------------------------------------------------------------------------- */

/* Read a small procfs file with the raw syscall, so nothing here re-enters the
 * wrappers below. These files are never larger than a few kilobytes and the
 * fields we want are at the front. */
static int real_open_raw(const char *path, int flags)
{
    static int (*resolved)(const char *, int, ...) = NULL;
    if (resolved == NULL) {
        resolved = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
        if (resolved == NULL) {
            return -1;
        }
    }
    return resolved(path, flags, 0);
}

static ssize_t slurp(const char *path, char *out, size_t size)
{
    /* The real open, not the wrapper below: slurp reads /proc/uptime itself
     * and would otherwise recurse forever. */
    int fd = real_open_raw(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t got = read(fd, out, size - 1);
    close(fd);
    if (got < 0) {
        return -1;
    }
    out[got] = '\0';
    return got;
}

/* Host boot, in seconds since the epoch, from /proc/stat's btime line. */
static long host_btime(void)
{
    char buf[8192];
    if (slurp("/proc/stat", buf, sizeof(buf)) < 0) {
        return -1;
    }
    const char *at = strstr(buf, "btime ");
    if (at == NULL) {
        return -1;
    }
    long value = 0;
    if (sscanf(at, "btime %ld", &value) != 1) {
        return -1;
    }
    return value;
}

/* PID 1's start, in clock ticks since host boot: field 22 of /proc/1/stat.
 *
 * Counted from after the command name, because that field is parenthesised and
 * may itself contain spaces or brackets -- parsing from the start of the line
 * is the classic way to get this wrong. */
static long init_start_ticks(void)
{
    char buf[4096];
    if (slurp("/proc/1/stat", buf, sizeof(buf)) < 0) {
        return -1;
    }
    const char *after = strrchr(buf, ')');
    if (after == NULL) {
        return -1;
    }
    after++;

    /* Field 3 (state) follows the name, so starttime is the 20th field from
     * here. */
    int field = 2;
    const char *cursor = after;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        field++;
        if (field == 22) {
            long ticks = 0;
            if (sscanf(cursor, "%ld", &ticks) != 1) {
                return -1;
            }
            return ticks;
        }
        while (*cursor != ' ' && *cursor != '\0') {
            cursor++;
        }
    }
    return -1;
}

/* Seconds this container has been up, or -1 if it cannot be established.
 *
 * Cached: the answer only changes when the container restarts, and this runs
 * in every process on the box. */
static double container_uptime(void)
{
    static long boot_epoch = 0;   /* 0 = not yet computed, -1 = unavailable */

    if (boot_epoch == 0) {
        long btime = host_btime();
        long ticks = init_start_ticks();
        long hz = sysconf(_SC_CLK_TCK);
        if (btime < 0 || ticks < 0 || hz <= 0) {
            boot_epoch = -1;
        } else {
            boot_epoch = btime + (ticks / hz);
        }
    }
    if (boot_epoch < 0) {
        return -1.0;
    }

    /* Host uptime plus host boot gives now without calling time(), keeping
     * this to the two files already being read. */
    char buf[128];
    if (slurp(UPTIME_PATH, buf, sizeof(buf)) < 0) {
        return -1.0;
    }
    double host_up = 0.0;
    double host_idle = 0.0;
    if (sscanf(buf, "%lf %lf", &host_up, &host_idle) < 1) {
        return -1.0;
    }
    long btime = host_btime();
    if (btime < 0) {
        return -1.0;
    }
    double up = (double)btime + host_up - (double)boot_epoch;
    return up > 0.0 ? up : 0.0;
}

/* A read-only fd holding what /proc/uptime should say.
 *
 * memfd so there is no file anywhere for an attacker to find, and no name in
 * /proc/PID/fd beyond an anonymous one -- which is what a memfd looks like for
 * plenty of ordinary software. */
static int synth_uptime_fd(void)
{
    double up = container_uptime();
    if (up < 0.0) {
        return -1;
    }

    /* Idle scaled from the host's own ratio rather than invented, so the
     * second field stays plausible against the first on any machine. */
    char host[128];
    double host_up = 0.0;
    double host_idle = 0.0;
    double ratio = 1.0;
    if (slurp(UPTIME_PATH, host, sizeof(host)) > 0 &&
        sscanf(host, "%lf %lf", &host_up, &host_idle) == 2 && host_up > 0.0) {
        ratio = host_idle / host_up;
    }

    char content[128];
    int len = snprintf(content, sizeof(content), "%.2f %.2f\n", up, up * ratio);
    if (len <= 0) {
        return -1;
    }

    int fd = memfd_create("uptime", 0U);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, content, (size_t)len) != (ssize_t)len ||
        lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int is_uptime(const char *path)
{
    return path != NULL && strcmp(path, UPTIME_PATH) == 0;
}

int open(const char *path, int flags, ...)
{
    static int (*real_open)(const char *, int, ...) = NULL;
    if (real_open == NULL) {
        real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
        if (real_open == NULL) {
            return -1;
        }
    }

    if (is_uptime(path) && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = synth_uptime_fd();
        if (fd >= 0) {
            return fd;
        }
        /* Fall through to the real file rather than failing the call. */
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(args, int) : 0;
    va_end(args);
    return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    static int (*real_open64)(const char *, int, ...) = NULL;
    if (real_open64 == NULL) {
        real_open64 = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
        if (real_open64 == NULL) {
            return -1;
        }
    }

    if (is_uptime(path) && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = synth_uptime_fd();
        if (fd >= 0) {
            return fd;
        }
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(args, int) : 0;
    va_end(args);
    return real_open64(path, flags, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (real_fopen == NULL) {
        real_fopen = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
        if (real_fopen == NULL) {
            return NULL;
        }
    }

    /* procps reads /proc/uptime with fopen, so this is the wrapper `uptime`,
     * `top` and `w` actually go through. */
    if (is_uptime(path) && mode != NULL && mode[0] == 'r') {
        int fd = synth_uptime_fd();
        if (fd >= 0) {
            FILE *stream = fdopen(fd, "r");
            if (stream != NULL) {
                return stream;
            }
            close(fd);
        }
    }
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    static FILE *(*real_fopen64)(const char *, const char *) = NULL;
    if (real_fopen64 == NULL) {
        real_fopen64 = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen64");
        if (real_fopen64 == NULL) {
            return NULL;
        }
    }

    if (is_uptime(path) && mode != NULL && mode[0] == 'r') {
        int fd = synth_uptime_fd();
        if (fd >= 0) {
            FILE *stream = fdopen(fd, "r");
            if (stream != NULL) {
                return stream;
            }
            close(fd);
        }
    }
    return real_fopen64(path, mode);
}
