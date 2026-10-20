/* SPDX-License-Identifier: MIT
 * Actual C80 helper, independent register/failure model. No SDK implementation.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "c80_rtl8367s.h"
static unsigned regs[65536], calls, fail_at, fail2, ignored_write, writes, id_reads;
static bool after_effect, unstable;
static unsigned checks, faults;
#define CHECK(x) do { assert(x); checks++; } while (0)
static bool fail(void) { return calls == fail_at || calls == fail2; }
static int rd(void *ctx, unsigned reg, unsigned *out)
{
    assert(ctx == regs); calls++;
    assert(reg == 0x13c2 || reg == 0x13c0 || reg == 0x1300 || reg == 0x1301 ||
           reg == 0x13c1 || reg == 0x1305 || reg == 0x1311 || reg == 0x1d11 || reg == 0x1d41);
    if (fail()) return -ETIMEDOUT;
    if (reg == 0x1300 || reg == 0x1301) assert(regs[0x13c2] == 0x249);
    if (reg == 0x13c1) assert(regs[0x13c0] == 0x249);
    *out = regs[reg];
    if (reg == 0x1300 && ++id_reads == 2 && unstable) *out ^= 1;
    return 0;
}
static int wr(void *ctx, unsigned reg, unsigned val)
{
    assert(ctx == regs); calls++; writes++;
    if (reg == 0x13c2 || reg == 0x13c0) assert(val == 0 || val == 0x249);
    else { assert(reg == 0x1311 || reg == 0x1d11);
           assert(reg == 0x1311 ? (val == 0x1016 || val == 0x1006) : (val == 0x1f00 || val == 0x1d00)); }
    if (fail() && !after_effect) return -ETIMEDOUT;
    if (calls != ignored_write) regs[reg] = val;
    return fail() ? -ETIMEDOUT : 0;
}
static struct c80_rtl_io io = {regs, rd, wr};
static void reset(bool up)
{
    memset(regs, 0, sizeof(regs));
    regs[0x1300] = 0x6367; regs[0x1301] = 0xa0; regs[0x13c1] = 1;
    regs[0x1305] = 0xc0a0; regs[0x1d41] = 0x1f;
    regs[0x1311] = up ? 0x1016 : 0x1006; regs[0x1d11] = up ? 0x1f00 : 0x1d00;
    calls = fail_at = fail2 = ignored_write = writes = id_reads = 0; after_effect = unstable = false;
}
int main(void)
{
    unsigned id, ver;
    for (unsigned up = 0; up < 2; up++) {
        reset(up); CHECK(!c80_rtl_guard(&io, &id, &ver)); CHECK(calls == 24 && writes == 6);
        CHECK(id == 0x6367 && ver == 0xa0 && !regs[0x13c0] && !regs[0x13c2]);
        CHECK(!c80_rtl_link(&io, !up)); CHECK(regs[0x1311] == (up ? 0x1006u : 0x1016u));
        CHECK(regs[0x1d11] == (up ? 0x1d00u : 0x1f00u));
        CHECK(!c80_rtl_link(&io, up)); CHECK(regs[0x1311] == (up ? 0x1016u : 0x1006u));
    }
    /* Refuse changed IDs, option, SerDes mode, ECO, mixed control states and
     * already-open protected banks; only key restoration writes are allowed. */
    unsigned badregs[] = {0x1300,0x1301,0x13c1,0x1305,0x1d41,0x1311,0x1d11,0x13c0,0x13c2};
    for (unsigned i = 0; i < sizeof(badregs)/sizeof(*badregs); i++) {
        reset(true); regs[badregs[i]] ^= 1;
        CHECK(c80_rtl_guard(&io,&id,&ver) < 0);
        CHECK(regs[0x1311] == (i == 5 ? 0x1017u : 0x1016u));
        CHECK(regs[0x1d11] == (i == 6 ? 0x1f01u : 0x1f00u));
    }
    reset(true); unstable = true; CHECK(c80_rtl_guard(&io,&id,&ver) == -ENODEV);
    for (unsigned at = 1; at <= 24; at++) for (unsigned apply = 0; apply < 2; apply++) {
        reset(true); fail_at = at; after_effect = apply;
        int rc = c80_rtl_guard(&io,&id,&ver); CHECK(rc < 0); faults++;
        CHECK(regs[0x1311] == 0x1016 && regs[0x1d11] == 0x1f00);
        CHECK((!regs[0x13c0] && !regs[0x13c2]) || rc == -EUCLEAN);
        CHECK(calls < 30);
    }
    for (unsigned initial = 0; initial < 2; initial++)
    for (unsigned at = 1; at <= 7; at++) for (unsigned apply = 0; apply < 2; apply++) {
        reset(initial); fail_at = at; after_effect = apply;
        CHECK(c80_rtl_link(&io,!initial) == -ETIMEDOUT); faults++;
        CHECK(regs[0x1311] == (initial ? 0x1016u : 0x1006u));
        CHECK(regs[0x1d11] == (initial ? 0x1f00u : 0x1d00u));
        CHECK(calls <= 11 && !regs[0x13c0] && !regs[0x13c2]);
    }
    /* Writes that report success but fail to change hardware are detected. */
    for (unsigned at = 4; at <= 5; at++) {
        reset(true); ignored_write = at; CHECK(c80_rtl_link(&io,false) == -EIO);
        CHECK(regs[0x1311] == 0x1016 && regs[0x1d11] == 0x1f00);
    }
    for (unsigned at = 6; at <= 9; at++) {
        reset(true); fail_at = 5; after_effect = true; fail2 = at;
        CHECK(c80_rtl_link(&io,false) == -EUCLEAN); CHECK(calls == 9); faults++;
    }
    for (unsigned key = 0; key < 2; key++) {
        reset(true); regs[key ? 0x13c0 : 0x13c2] = 0x249;
        CHECK(c80_rtl_guard(&io,&id,&ver) == -EINVAL);
        CHECK(regs[key ? 0x13c0 : 0x13c2] == 0x249);
    }
    reset(true); regs[0x1311] = 0x1006; CHECK(c80_rtl_link(&io,false) == -EINVAL && !writes);
    printf("PASS: %u checks; %u injected failures; actual DSA control helper, independent register model\n",checks,faults);
    return 0;
}
