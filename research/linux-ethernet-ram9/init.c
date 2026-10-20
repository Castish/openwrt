/* SPDX-License-Identifier: MIT
 * Freestanding RAM PID 1 with read-only flash and manual IPv4 setup.
 */
void *memset(void *destination, int value, unsigned count)
{
    volatile unsigned char *out = destination;
    while (count--) *out++ = (unsigned char)value;
    return destination;
}

static long syscall5(long nr, long a, long b, long c, long d, long e)
{
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r4 __asm__("r4") = e;
    register long r7 __asm__("r7") = nr;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3),
                     "r"(r4), "r"(r7) : "memory", "cc");
    return r0;
}

static unsigned length(const char *s)
{
    unsigned n = 0;
    while (s[n]) ++n;
    return n;
}

static void write_all(const char *s, unsigned n)
{
    while (n) {
        long rc = syscall5(4, 1, (long)s, n, 0, 0);
        if (rc == -4) continue;
        if (rc <= 0) return;
        s += rc;
        n -= (unsigned)rc;
    }
}

static void say(const char *s) { write_all(s, length(s)); }

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static int prefix(const char *text, const char *start)
{
    while (*start) if (*text++ != *start++) return 0;
    return 1;
}

static void show_file(const char *name)
{
    char buffer[512];
    long fd = syscall5(5, (long)name, 0, 0, 0, 0);
    if (fd < 0) { say("Cannot open requested file.\n"); return; }
    for (;;) {
        long n = syscall5(3, fd, (long)buffer, sizeof(buffer), 0, 0);
        if (n == -4) continue;
        if (n <= 0) break;
        write_all(buffer, (unsigned)n);
    }
    syscall5(6, fd, 0, 0, 0, 0);
}

/* Snapshot the existing printk buffer, without clearing or changing it. */
static void kernel_log(void)
{
    static char buffer[65536];
    long rc;
    do { rc = syscall5(103, 3, (long)buffer, sizeof(buffer), 0, 0); } while (rc == -4);
    if (rc < 0) { say("Cannot read kernel log.\n"); return; }
    if ((unsigned long)rc > sizeof(buffer)) { say("Invalid kernel log length.\n"); return; }
    write_all(buffer, (unsigned)rc);
}

#include "flash-reader.inc"
#include "net-commands.inc"

void _start(void) __attribute__((noreturn));
void _start(void)
{
    crc_init();
    long fd = syscall5(5, (long)"/dev/console", 2, 0, 0, 0);
    if (fd >= 0) {
        for (long i = 0; i < 3; ++i) syscall5(63, fd, i, 0, 0, 0);
        if (fd > 2) syscall5(6, fd, 0, 0, 0, 0);
    }
    syscall5(21, (long)"devtmpfs", (long)"/dev", (long)"devtmpfs", 0, 0);
    if (syscall5(21, (long)"proc", (long)"/proc", (long)"proc", 0, 0) < 0)
        say("Warning: procfs mount failed.\n");
    syscall5(21, (long)"sysfs", (long)"/sys", (long)"sysfs", 0, 0);
    say("\nC80 Linux RAM userspace ready.\n");
    say("Commands: help, version, cpu, mem, irq, flash, backup, netup, netdown, net, switch, dsa, dmesg, ports; port lan1|lan2|lan3|lan4|wan.\n");
    for (;;) {
        char line[64];
        unsigned n = 0;
        say("c80-linux> ");
        for (;;) {
            char c;
            long rc = syscall5(3, 0, (long)&c, 1, 0, 0);
            if (rc == -4) continue;
            if (rc <= 0) { syscall5(29, 0, 0, 0, 0, 0); continue; }
            if (c == '\n' || c == '\r') break;
            if (c >= 32 && c < 127 && n < sizeof(line) - 1) line[n++] = c;
        }
        line[n] = 0;
        if (equal(line, "help")) say("Commands: help, version, cpu, mem, irq, flash, backup, netup, netdown, net, switch, dsa, dmesg, ports; port lan1|lan2|lan3|lan4|wan.\n");
        else if (equal(line, "version")) show_file("/proc/version");
        else if (equal(line, "cpu")) show_file("/proc/cpuinfo");
        else if (equal(line, "mem")) show_file("/proc/meminfo");
        else if (equal(line, "irq")) show_file("/proc/interrupts");
        else if (equal(line, "flash")) { show_file("/proc/mtd"); flash_command(0); }
        else if (equal(line, "backup")) flash_command(1);
        else if (equal(line, "netup")) net_configure(1);
        else if (equal(line, "netdown")) net_configure(0);
        else if (equal(line, "net")) net_show();
        else if (equal(line, "dmesg")) kernel_log();
        else if (equal(line, "ports")) net_ports();
        else if (equal(line, "port")) net_port_command("");
        else if (prefix(line, "port ")) net_port_command(line + 5);
        else if (equal(line, "switch")) show_file("/sys/class/net/eth0/device/switch_state");
        else if (equal(line, "dsa")) dsa_show();
        else if (n) say("Unknown command; enter help.\n");
    }
}
