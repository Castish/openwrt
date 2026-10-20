/* SPDX-License-Identifier: MIT
 * Linux API/MDIO protocol model for the actual c80_ram_mdio.c.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>

typedef uint32_t u32;
typedef uint16_t u16;
#define __iomem
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MII_BUS_ID_SIZE 61
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))

struct mutex { pthread_mutex_t native; };
static _Thread_local bool lock_held;
static void mutex_lock(struct mutex *m) { assert(!lock_held); assert(!pthread_mutex_lock(&m->native)); lock_held = true; }
static void mutex_unlock(struct mutex *m) { assert(lock_held); lock_held = false; assert(!pthread_mutex_unlock(&m->native)); }
struct device { void (*action)(void *); void *data; };
struct mii_bus {
    const char *name;
    char id[MII_BUS_ID_SIZE];
    struct device *parent;
    void *priv;
    u32 phy_mask;
    int (*read)(struct mii_bus *, int, int);
    int (*write)(struct mii_bus *, int, int, u16);
    struct mutex mdio_lock;
};
static unsigned char fe[0x20000] __attribute__((aligned(64)));
static u16 asic[0x10000], initial_id_key, initial_option_key, smi_target, smi_data;
static unsigned smi_phase, commands, writes, completed, busy_reads, poll_reads, paced;
static unsigned id_reads, version_reads, key_reads[2], fail_command;
static bool fail_after_apply, permanent_busy, busy, flip_config, bad_unlock_id, bad_unlock_option;
static bool bad_restore_id, bad_restore_option, wrong_second_id;
static bool link_testing, hold_link_up, hold_link_down, ignore_off_write, ignore_restore_write;
static unsigned link_writes, down_delay, up_delay, link_reads, transition_reads, sleeps;
static u32 dma_config, dma_mask;
static unsigned jam_command;
static u32 latch, command_result, mdio_config;
static int fail_alloc, fail_register, fail_action;
static unsigned buses_live, registrations, unregistrations;
static _Thread_local unsigned completed_snapshots;

static u16 smi_get(u16 reg)
{
    assert(reg == 0x13c2 || reg == 0x13c0 || reg == 0x1300 || reg == 0x1301 ||
           reg == 0x13c1 || reg == 0x1305 || reg == 0x1311 || reg == 0x1d11 || reg == 0x1d41 ||
           (reg >= 0x1352 && reg <= 0x1356) || reg == 0x1358);
    if (reg == 0x1300 || reg == 0x1301) {
        assert(asic[0x13c2] == 0x249);
        if (reg == 0x1300) { id_reads++; if (wrong_second_id && id_reads == 2) return 0x6368; }
        else version_reads++;
    }
    if (reg == 0x13c1) { assert(asic[0x13c0] == 0x249); assert(asic[0x13c2] == initial_id_key); }
    if (reg == 0x13c2 || reg == 0x13c0) {
        unsigned i = reg == 0x13c0;
        key_reads[i]++;
        if (key_reads[i] == 2 && (i ? bad_unlock_option : bad_unlock_id)) return 0;
        if (key_reads[i] == 3 && (i ? bad_restore_option : bad_restore_id)) return 0x1234;
    }
    if (reg == 0x1305 || reg == 0x1311 || reg == 0x1d11 || reg == 0x1d41 ||
        (reg >= 0x1352 && reg <= 0x1356) || reg == 0x1358) {
        assert(asic[0x13c2] == initial_id_key && asic[0x13c0] == initial_option_key);
    }
    if (link_testing && reg == 0x1358) {
        link_reads++;
        bool up = (asic[0x1311] & 0x10) && (asic[0x1d11] & 0x200);
        if (hold_link_up) up = true;
        if (hold_link_down && link_writes) up = false;
        if (up && transition_reads && up_delay) { up_delay--; up = false; }
        if (!up && down_delay) { down_delay--; up = true; }
        return (asic[reg] & ~0x10) | (up ? 0x10 : 0);
    }
    return asic[reg];
}

/* Independent Clause22 and Realtek SMI decoder, not production helpers. */
static void apply_command(u32 command)
{
    unsigned phy = command >> 20 & 31, reg = command >> 25 & 31;
    unsigned op = command >> 18 & 3, st = command >> 16 & 3;
    u16 data = command;
    assert(lock_held && phy == 29 && st == 1 && (op == 1 || op == 2));
    completed++;
    command_result = 0;
    if (op == 2) {
        assert(reg == 25 && smi_phase == 3);
        command_result = smi_get(smi_target); smi_phase = 0;
    } else if (reg == 31) {
        assert(data == 14); smi_phase = 1;
    } else if (smi_phase == 1) {
        assert(reg == 23); smi_target = data; smi_phase = 2;
    } else if (smi_phase == 2 && reg == 21) {
        assert(data == 1); smi_phase = 3;
    } else if (smi_phase == 2 && reg == 24) {
        smi_data = data; smi_phase = 4;
    } else if (smi_phase == 4) {
        assert(reg == 21 && data == 3);
        if (smi_target == 0x13c2 || smi_target == 0x13c0) {
            assert(smi_data == 0 || smi_data == 0x249);
            asic[smi_target] = smi_data;
        } else {
            assert(link_testing && (smi_target == 0x1311 || smi_target == 0x1d11));
            unsigned bit = smi_target == 0x1311 ? 0x10 : 0x200;
            u16 original = smi_target == 0x1311 ? 0x1016 : 0x1f00;
            assert(smi_data == original || smi_data == (original & ~bit));
            assert(asic[0x13c2] == initial_id_key && asic[0x13c0] == initial_option_key);
            link_writes++;
            bool restore = smi_data == original;
            if (!(restore ? ignore_restore_write : ignore_off_write)) asic[smi_target] = smi_data;
            if (restore) transition_reads++;
        }
        smi_phase = 0;
    } else assert(!"Malformed SMI sequence or unapproved write");
}

static u32 readl(const void *address)
{
    assert(lock_held);
    uintptr_t offset = (const unsigned char *)address - fe;
    if (offset == 0xa04) return dma_config;
    if (offset == 0xa28) return dma_mask;
    if (offset == 0x10000) return mdio_config;
    assert(offset == 0x10004); poll_reads++;
    if (busy && (permanent_busy || busy_reads)) {
        if (busy_reads) busy_reads--;
        return 0x80000000;
    }
    busy = false;
    return command_result;
}
static void writel(u32 value, void *address)
{
    assert(lock_held && address == fe + 0x10004);
    writes++;
    if (!(value & 0x80000000)) { assert(!busy); latch = value; return; }
    assert(value == (latch | 0x80000000));
    commands++; busy = true; busy_reads = commands == fail_command ? 100 : 2;
    if (commands != fail_command || fail_after_apply) apply_command(latch);
    if (commands == jam_command) permanent_busy = true;
    if (flip_config && commands == 100) mdio_config ^= 1;
}
#define readl_poll_timeout(address, value, condition, interval, timeout) ({ \
    assert((interval) == 1 && (timeout) == 100000); \
    int result = -ETIMEDOUT; \
    for (unsigned n = 0; n < 100; n++) { value = readl(address); if (condition) { result = 0; break; } } \
    result; })
static void usleep_range(unsigned low, unsigned high) { assert(lock_held && low == 20 && high == 40); paced++; }
static void msleep(unsigned time) { assert(lock_held && time == 10); sleeps++; }
static int __mdiobus_read(struct mii_bus *b, int phy, u32 reg) { assert(lock_held); return b->read(b, phy, reg); }
static int __mdiobus_write(struct mii_bus *b, int phy, u32 reg, u16 val) { assert(lock_held); return b->write(b, phy, reg, val); }
static void strscpy(char *to, const char *from, size_t len) { assert(strlen(from) < len); strcpy(to, from); }
static ssize_t sysfs_emit(char *buf, const char *format, ...)
{
    assert(!lock_held); completed_snapshots++;
    va_list args; va_start(args, format); int n = vsnprintf(buf, 4096, format, args); va_end(args);
    assert(n > 0 && n < 4096); return n;
}
static struct mii_bus *mdiobus_alloc_size(size_t size)
{
    if (fail_alloc) return NULL;
    struct mii_bus *b = calloc(1, sizeof(*b) + size); assert(b);
    b->priv = b + 1; buses_live++; return b;
}
static int mdiobus_register(struct mii_bus *b)
{
    assert(b->name && b->parent && b->read && b->write && b->phy_mask == 0xffffffffU);
    assert(!strcmp(b->id, "c80-ram-mdio"));
    if (fail_register) return fail_register;
    assert(!pthread_mutex_init(&b->mdio_lock.native, NULL)); registrations++; return 0;
}
static void mdiobus_unregister(struct mii_bus *b) { assert(!lock_held); assert(!pthread_mutex_destroy(&b->mdio_lock.native)); unregistrations++; }
static void mdiobus_free(struct mii_bus *b) { assert(buses_live); buses_live--; free(b); }
static int devm_add_action_or_reset(struct device *dev, void (*action)(void *), void *data)
{
    if (fail_action) { action(data); return fail_action; }
    assert(!dev->action); dev->action = action; dev->data = data; return 0;
}
