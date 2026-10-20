/* SPDX-License-Identifier: MIT
 * Early-entry extension inside the installed normal U-Boot binary.
 * Uses the exact factory U-Boot callbacks before normal U-Boot initialises.
 * Native callbacks own the Ethernet/TFTP/cache operations. This parser does
 * not provide a shell, nor a security boundary around downloaded ARM code.
 */
typedef unsigned int u32;
typedef unsigned char u8;

#define RAM_MIN       0x40200000u
#define PAYLOAD_END   0x41c00000u
#define RAM_END       0x42000000u
#define RUNNER        0x40280000u
#define SCRIPT        0x40a00000u
#define RESERVED_SIZE 0x10000u
#define SCRIPT_MAX    4096u
#define MAX_STEPS     16u
#define LOADER_SIZE   185636u

typedef int (*command_fn)(void *, int, int, char *const []);
typedef char *(*getenv_fn)(const char *);
struct step { u32 kind, address, size, crc, line; char *file; };
struct context { u32 base, uart_failed, line, count; struct step steps[MAX_STEPS]; };

static u32 read32(u32 address) { return *(volatile u32 *)address; }

static void putc_c80(struct context *c, char ch)
{
    u32 i;
    if (c->uart_failed) return;
    for (i = 0; i < 1000000; ++i) {
        if (read32(0x11002014) & 0x20) {
            *(volatile u32 *)0x11002000 = (u8)ch;
            return;
        }
    }
    c->uart_failed = 1;
}

static void out(struct context *c, const char *s)
{
    while (*s && !c->uart_failed) putc_c80(c, *s++);
}

static void hex_string(u32 value, char s[9])
{
    u32 i;
    for (i = 0; i < 8; ++i) {
        s[i] = "0123456789abcdef"[value >> 28];
        value <<= 4;
    }
    s[8] = 0;
}

static __attribute__((noinline)) int fail(struct context *c,u32 code,const char *reason)
{
    (void)reason; out(c,"C80 TFTP fallback\r\n"); return (int)code;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

/* Input is bounded by a terminated script token or by env_number(). */
static int number(const char *s, u32 *value)
{
    u32 n = 0, digits = 0, v;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) {
        if (*s >= '0' && *s <= '9') v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') v = *s - 'A' + 10;
        else return 0;
        if (++digits > 8) return 0;
        n = (n << 4) | v;
        ++s;
    }
    *value = n;
    return digits != 0;
}

static u32 crc32(const u8 *p, u32 size)
{
    u32 crc = ~0u, j;
    while (size--) {
        crc ^= *p++;
        for (j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    return ~crc;
}

static int fingerprint(u32 base, u32 offset, u32 size, u32 expected)
{
    return crc32((const u8 *)(base + offset), size) == expected;
}

static int command_profile(u32 base, u32 entry, u32 name, u32 maxargs,
                           u32 repeatable, u32 function, const char *text)
{
    const u32 *t = (const u32 *)(base + entry);
    return t[0] == base + name && t[1] == maxargs && t[2] == repeatable &&
           t[3] == base + function && equal((const char *)(base + name), text);
}

static int loader_profile(u32 base)
{
    return fingerprint(base, 0x271c, 16, 0x12c2ca49) &&
           fingerprint(base, 0x272c, 32, 0x08c88ba2) &&
           fingerprint(base, 0x37ec, 32, 0x8dcc7333) &&
           fingerprint(base, 0x41e0, 32, 0xdd7368a2) &&
           fingerprint(base, 0x4624, 32, 0xa0c420f0) &&
           command_profile(base, 0x29f58, 0x23858, 8, 1, 0x272c, "go") &&
           command_profile(base, 0x29ff8, 0x23fc5, 8, 0, 0x41e0, "setenv") &&
           command_profile(base, 0x2a020, 0x23d2b, 3, 1, 0x37ec, "tftpboot");
}

static char *env(struct context *c, const char *name)
{
    return ((getenv_fn)(c->base + 0x4624))(name);
}

static int env_number(struct context *c, const char *name, u32 *value)
{
    const char *s = env(c, name);
    char copy[11];
    u32 i, a = (u32)s;
    if (a < PAYLOAD_END || a > RAM_END - sizeof(copy)) return 0;
    for (i = 0; i < sizeof(copy); ++i) {
        copy[i] = s[i];
        if (!copy[i]) return number(copy, value);
    }
    return 0;
}

static int set_option(struct context *c, const char *key, const char *value)
{
    char *args[] = { "setenv", (char *)key, (char *)value };
    const char *s; u32 a;
    if (((command_fn)(c->base + 0x41e0))((void *)(c->base + 0x29ff8),0,3,args)) return 0;
    s=env(c,key); a=(u32)s;
    return a >= PAYLOAD_END && a <= RAM_END - 32 && equal(s,value);
}

static int download(struct context *c, u32 address, char *file, u32 *size)
{
    char addr[9];
    char *args[] = { "tftpboot", addr, file };
    int rc;
    hex_string(address, addr);
    rc = ((command_fn)(c->base + 0x37ec))((void *)(c->base + 0x2a020), 0, 3, args);
    return rc == 0 && env_number(c, "filesize", size);
}

static int overlap(u32 a, u32 n, u32 b, u32 m)
{
    /* All callers validate non-wrapping input intervals first. */
    return a < b + m && b < a + n;
}

static int payload_range(u32 a, u32 size)
{
    return !(a & 3) && size && a >= RAM_MIN && a < PAYLOAD_END &&
           size <= PAYLOAD_END - a &&
           !overlap(a, size, RUNNER, RESERVED_SIZE) &&
           !overlap(a, size, SCRIPT, RESERVED_SIZE);
}

static int filename(const char *s)
{
    u32 n = 0;
    while (*s) {
        char c = *s++;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return 0;
        if (++n > 95) return 0;
    }
    return n && !(n == 1 && s[-1] == '.') &&
           !(n == 2 && s[-1] == '.' && s[-2] == '.');
}

/* Validate the ENTIRE script before any payload download/entry. */
static int parse(struct context *c, char *script, u32 size)
{
    char *p, *e, *words[5];
    u32 i, n, header = 0, ended = 0;
    for (i = 0; i < size; ++i) {
        u8 v = (u8)script[i];
        if (i < 3 && size >= 3 && (u8)script[0] == 0xef &&
            (u8)script[1] == 0xbb && (u8)script[2] == 0xbf) continue;
        if ((v < 32 && v != '\r' && v != '\n' && v != '\t') || v > 126)
            return fail(c, 20, "non-ASCII/control byte");
    }
    script[size] = 0;
    p = script;
    if (size >= 3 && (u8)p[0] == 0xef) p += 3;
    while (*p) {
        ++c->line;
        e = p;
        while (*e && *e != '\n' && *e != '\r') ++e;
        if (*e) { char ch = *e; *e++ = 0; if (ch == '\r' && *e == '\n') ++e; }
        n = 0;
        while (*p) {
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p || *p == '#') break;
            if (n == 5) return fail(c, 21, "too many tokens");
            words[n++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '#') ++p;
            if (*p == '#') { *p = 0; break; }
            if (*p) *p++ = 0;
        }
        p = e;
        if (!n) continue;
        if (!header) {
            if (n != 1 || !equal(words[0], "C80SCRIPT1")) return fail(c, 22, "missing C80SCRIPT1 header");
            header = 1;
            continue;
        }
        if (ended) return fail(c, 23, "command after end");
        if (n == 1 && equal(words[0], "end")) { ended = 1; continue; }
        if (c->count == MAX_STEPS) return fail(c, 24, "too many steps");
        struct step *s = &c->steps[c->count];
        s->line = c->line;
        if (n == 5 && equal(words[0], "load")) {
            s->kind = 1; s->file = words[2];
            if (!number(words[1], &s->address) || !number(words[3], &s->size) ||
                !number(words[4], &s->crc) || !filename(s->file)) return fail(c, 25, "bad load argument");
            if (!payload_range(s->address, s->size)) return fail(c, 26, "load outside permitted RAM");
            for (i = 0; i < c->count; ++i)
                if (c->steps[i].kind == 1 && overlap(s->address, s->size,
                    c->steps[i].address, c->steps[i].size)) return fail(c, 27, "overlapping loads");
        } else if (n == 2 && equal(words[0], "go")) {
            s->kind = 2;
            if (!number(words[1], &s->address)) return fail(c, 28, "bad go address");
            for (i = 0; i < c->count; ++i)
                if (c->steps[i].kind == 1 && c->steps[i].address == s->address) break;
            if (i == c->count) return fail(c, 29, "go without preceding load");
            s->size = c->steps[i].size; s->crc = c->steps[i].crc;
        } else return fail(c, 30, "unsupported command/syntax");
        ++c->count;
    }
    if (!header || !ended) return fail(c, 31, "header/end required");
    return 0;
}

int c80_netboot(u32 caller, u32 original_sp)
{
    struct context c;
    u32 cpsr, midr, gd, size, i, actual;
    int rc;
    c.base = caller - 0x2700; c.uart_failed = 0; c.line = 0; c.count = 0;
    out(&c, "\r\nU-Boot C80 native AutoTFTP v1\r\n");
    if (c.uart_failed) return 40;
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(midr));
    __asm__ volatile("mov %0, r9" : "=r"(gd));
    if ((cpsr & 0x3ff) != 0x1d3 || midr != 0x410fc073) return fail(&c, 3, "CPU/mode mismatch");
    if ((c.base & 0xfff) || c.base < PAYLOAD_END || c.base > RAM_END - LOADER_SIZE ||
        (gd & 3) || gd < PAYLOAD_END || gd >= RAM_END - 256 ||
        (original_sp & 3) || original_sp < PAYLOAD_END + 0x10000 || original_sp >= RAM_END)
        return fail(&c, 4, "loader/GD/stack outside expected RAM");
    if (!loader_profile(c.base)) return fail(&c, 5, "factory loader profile mismatch");
    if (c.uart_failed) return 40;
    if (!set_option(&c,"autostart","no") ||
        !set_option(&c,"ipaddr","192.168.0.1") ||
        !set_option(&c,"serverip","192.168.0.3") ||
        !set_option(&c,"netretry","no") ||
        !set_option(&c,"tftptimeout","1000"))
        return fail(&c, 6, "cannot set TFTP options");
    if (c.uart_failed) return 40;
    if (!download(&c, SCRIPT, "c80-start.txt", &size)) return fail(&c, 7, "script TFTP/filesize failed");
    if (!size || size > SCRIPT_MAX) return fail(&c, 8, "script size must be 1..4096 bytes");
    rc = parse(&c, (char *)SCRIPT, size);
    if (rc) return rc;
    if (c.uart_failed) return 40;
    for (i = 0; i < c.count; ++i) {
        struct step *s = &c.steps[i];
        c.line = s->line;
        if (s->kind == 1) {
            if (c.uart_failed) return 40;
            if (!download(&c, s->address, s->file, &actual)) return fail(&c, 32, "payload TFTP/filesize failed");
            if (actual != s->size) return fail(&c, 33, "payload length mismatch");
        }
        actual = crc32((const u8 *)s->address, s->size);
        if (actual != s->crc) {
            return fail(&c, 34, "payload CRC mismatch");
        }
        if (s->kind == 1) {
            /* Native TFTP prints each filename; CRC failure aborts. */
        } else {
            char addr[9];
            char *args[] = { "go", addr };
            hex_string(s->address, addr);
            if (c.uart_failed) return 40;
            rc = ((command_fn)(c.base + 0x272c))((void *)(c.base + 0x29f58), 0, 2, args);
            if (rc) return fail(&c, 35, "application returned failure");
        }
        if (c.uart_failed) return 40;
    }
    return 0;
}
