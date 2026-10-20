/* SPDX-License-Identifier: MIT */
#include "mdio-test-shim.h"
#include "mdio-under-test.inc"

static unsigned checks;
#define CHECK(e) do { assert(e); checks++; } while (0)

static void reset_model(void)
{
    CHECK(!buses_live && !lock_held);
    memset(fe, 0x5a, sizeof(fe)); memset(asic, 0, sizeof(asic));
    commands = writes = completed = poll_reads = paced = busy_reads = 0;
    id_reads = version_reads = key_reads[0] = key_reads[1] = 0;
    fail_command = 0; fail_after_apply = permanent_busy = busy = flip_config = false;
    bad_unlock_id = bad_unlock_option = bad_restore_id = bad_restore_option = wrong_second_id = false;
    fail_alloc = fail_register = fail_action = 0;
    registrations = unregistrations = 0;
    smi_phase = smi_target = smi_data = latch = command_result = 0;
    initial_id_key = initial_option_key = 0;
    mdio_config = 0x45000504;
    asic[0x1300] = 0x6367; asic[0x1301] = 0xa0; asic[0x13c1] = 1;
    asic[0x1305] = 0xc0a0; asic[0x1311] = 0x1016; asic[0x1d11] = 0x1f00; asic[0x1d41] = 0x1f;
    for (unsigned i = 0; i < 5; i++) asic[0x1352+i] = i == 1 ? 0x196 : 0xe0;
    asic[0x1358] = 0x16;
}
static struct mii_bus *start(struct device *dev)
{
    *dev = (struct device){};
    struct mii_bus *bus = c80_mdio_register(dev, fe);
    CHECK(!IS_ERR(bus) && buses_live == 1 && !commands && !writes);
    return bus;
}
static void stop(struct device *dev)
{
    CHECK(dev->action && !lock_held); dev->action(dev->data); dev->action = NULL;
    CHECK(!buses_live && registrations == unregistrations);
    for (unsigned i = 0; i < sizeof(fe); i++) assert(fe[i] == 0x5a);
}
static struct c80_switch_snapshot snapshot(struct mii_bus *bus)
{
    struct c80_switch_snapshot s = {};
    c80_switch_read(bus, &s); CHECK(!lock_held); return s;
}
static void success(struct c80_switch_snapshot *s)
{
    CHECK(!s->result && !s->cleanup_errors && !s->tainted);
    CHECK(s->commands == 100 && s->stage == 85 && s->config_valid == 4 && s->ports_valid == 6);
    CHECK(s->id[0] == 0x6367 && s->id[1] == 0x6367 && s->version[0] == 0xa0 && s->version[1] == 0xa0);
    CHECK(s->option_valid && s->option == asic[0x13c1] && s->link_mask == 0x42);
    CHECK(!memcmp(s->cpu, (u16[]){0xc0a0,0x1016,0x1f00,0x1f}, sizeof(s->cpu)));
    CHECK(s->id_key.saved && s->id_key.restored && !s->id_key.dirty && s->id_key.after == initial_id_key);
    CHECK(s->option_key.saved && s->option_key.restored && !s->option_key.dirty && s->option_key.after == initial_option_key);
    CHECK(asic[0x13c2] == initial_id_key && asic[0x13c0] == initial_option_key);
    CHECK(s->config_before == 0x45000504 && s->config_after == s->config_before);
}

static void *concurrent_snapshot(void *opaque)
{
    struct mii_bus *bus = opaque;
    for (unsigned i = 0; i < 20; i++) {
        char buf[4096]; ssize_t n = c80_mdio_snapshot(bus, buf);
        assert(n > 0 && n < 4096 && strstr(buf, "result=0 cleanup_errors=00000000 tainted=0"));
        assert(strstr(buf, "commands=100") && strstr(buf, "option13c1=0001 valid=1 config_valid=4 ports_valid=6"));
    }
    assert(completed_snapshots == 20); return NULL;
}

int main(void)
{
    struct device dev;
    struct mii_bus *bus;
    struct c80_switch_snapshot s;
    unsigned failure_cases = 0;
    /* Actual hardware values, all original-key combinations, option zero. */
    for (unsigned keys = 0; keys < 4; keys++) {
        reset_model();
        initial_id_key = asic[0x13c2] = keys & 1 ? 0x249 : 0;
        initial_option_key = asic[0x13c0] = keys & 2 ? 0x249 : 0;
        if (keys == 3) asic[0x13c1] = 0;
        bus = start(&dev);
        for (unsigned repeat = 0; repeat < 3; repeat++) { s = snapshot(bus); success(&s); }
        stop(&dev);
    }
    /* Inject a one-command timeout at every transfer of the successful path,
     * both before and after its hardware side effect. Include key restores.
     */
    for (unsigned apply = 0; apply < 2; apply++) for (unsigned at = 1; at <= 100; at++) {
        reset_model(); bus = start(&dev); fail_command = at; fail_after_apply = apply;
        s = snapshot(bus); failure_cases++;
        CHECK(s.result == -ETIMEDOUT || s.result == -EUCLEAN);
        CHECK(s.commands <= 108 && poll_reads < 1000);
        CHECK(mdio_config == 0x45000504 && !lock_held);
        if (s.cleanup_errors) {
            CHECK(s.tainted);
            unsigned before = commands; struct c80_switch_snapshot again = snapshot(bus);
            CHECK(again.result == -EUCLEAN && again.tainted && !again.commands && commands == before);
        } else {
            CHECK(!s.tainted && asic[0x13c2] == initial_id_key && asic[0x13c0] == initial_option_key);
            fail_command = 0; s = snapshot(bus); success(&s);
        }
        stop(&dev);
    }
    /* No option/config/port access for an unknown or unstable ID/version. */
    for (unsigned bad = 0; bad < 3; bad++) {
        reset_model(); bus = start(&dev);
        if (bad == 0) asic[0x1300] = 0x6368;
        if (bad == 1) asic[0x1301] = 0xb0;
        if (bad == 2) wrong_second_id = true;
        s = snapshot(bus);
        CHECK(s.result == -ENODEV && !s.cleanup_errors && !s.option_key.saved && !s.option_valid);
        CHECK(!s.config_valid && !s.ports_valid && !asic[0x13c2] && !asic[0x13c0]); stop(&dev);
    }
    /* Invalid original keys refuse mutation and preserve the unknown value. */
    for (unsigned option = 0; option < 2; option++) {
        reset_model(); bus = start(&dev); asic[option ? 0x13c0 : 0x13c2] = 0x1234;
        s = snapshot(bus); CHECK(s.result == -EPERM && !s.cleanup_errors && !s.tainted);
        CHECK(asic[option ? 0x13c0 : 0x13c2] == 0x1234 && !s.option_valid); stop(&dev);
    }
    /* Readback errors, including incorrect confirmation of restoration. */
    for (unsigned bad = 0; bad < 4; bad++) {
        reset_model(); bus = start(&dev);
        switch (bad) { case 0: bad_unlock_id = true; break; case 1: bad_unlock_option = true; break;
        case 2: bad_restore_id = true; break; case 3: bad_restore_option = true; break; }
        s = snapshot(bus); CHECK(s.result < 0 && !asic[0x13c2] && !asic[0x13c0]);
        CHECK((bad < 2 && !s.cleanup_errors && !s.tainted) || (bad >= 2 && s.cleanup_errors && s.tainted)); stop(&dev);
    }
    /* Initial busy and permanently stalled bus: bounded, no new configuration. */
    reset_model(); bus = start(&dev); busy = permanent_busy = true;
    s = snapshot(bus); CHECK(s.result == -ETIMEDOUT && !commands && !writes && poll_reads == 100); stop(&dev);
    reset_model(); bus = start(&dev); fail_command = 8; fail_after_apply = true;
    /* A transient timeout already tests partial unlock recovery; model a bus
     * that stays busy after a successful open using a separate direct close. */
    mutex_lock(&bus->mdio_lock); struct c80_key key = {.reg=0x13c2}; fail_command = 0;
    CHECK(!c80_key_open(bus, &key)); busy = permanent_busy = true;
    u32 errors = 0; c80_key_close(bus, &key, &errors, 0); mutex_unlock(&bus->mdio_lock);
    CHECK(errors == 3 && key.dirty && !key.restored && asic[0x13c2] == 0x249 && poll_reads < 300); stop(&dev);
    /* Inherited MDIO config is required and must remain unchanged. */
    reset_model(); bus = start(&dev); mdio_config ^= 1;
    s = snapshot(bus); CHECK(s.result == -EINVAL && !s.commands && !s.cleanup_errors); stop(&dev);
    reset_model(); bus = start(&dev); flip_config = true;
    s = snapshot(bus); CHECK(s.result == -EUCLEAN && s.cleanup_errors == 0x40 && s.tainted); stop(&dev);
    /* Public helper cannot issue switch configuration or unknown key values. */
    reset_model(); bus = start(&dev); mutex_lock(&bus->mdio_lock);
    CHECK(c80_smi_key_write(bus, 0x1305, 0) == -EPERM);
    CHECK(c80_smi_key_write(bus, 0x13c2, 1) == -EPERM);
    CHECK(c80_mdio_read(bus, -1, 0) == -EINVAL && c80_mdio_read(bus, 32, 0) == -EINVAL);
    CHECK(c80_mdio_write(bus, 29, -1, 0) == -EINVAL && c80_mdio_write(bus, 29, 32, 0) == -EINVAL);
    mutex_unlock(&bus->mdio_lock); CHECK(!commands && !writes); stop(&dev);
    /* Bus setup has no reads/writes or scanned devices; allocation/register/
     * devres failures release their allocations and registrations exactly once. */
    for (unsigned at = 0; at < 3; at++) {
        reset_model(); dev = (struct device){};
        if (at == 0) fail_alloc = 1; if (at == 1) fail_register = -EIO; if (at == 2) fail_action = -ENOMEM;
        bus = c80_mdio_register(&dev, fe);
        CHECK(IS_ERR(bus) && !buses_live && !dev.action && !commands && !writes);
        CHECK(registrations == unregistrations);
    }
    /* Four concurrent sysfs readers: SMI latches/keys cannot interleave. */
    reset_model(); bus = start(&dev); pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_create(&threads[i], NULL, concurrent_snapshot, bus));
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_join(threads[i], NULL));
    CHECK(commands == 8000 && !asic[0x13c2] && !asic[0x13c0]); stop(&dev);
    printf("PASS: %u checks; %u injected transfer failures; 80 concurrent snapshots; actual MDIO C, independent protocol model\n", checks, failure_cases);
    return 0;
}
