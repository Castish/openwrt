// SPDX-License-Identifier: GPL-2.0-only
/*
 * MT7626 RAM bring-up: measured Clause22 controller and RTL8367S snapshot.
 * The bus has no scanned devices, reset callback, GPIO, or DT children.
 * Snapshot writes only the SMI transport latches and two temporary keys;
 * no port, VLAN, PHY, SerDes, DMA, clock, reset, or flash configuration.
 * Full multi-transfer SMI sequences and key cleanup share one MDIO mutex.
 */
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/phy.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include "c80_ram_mdio.h"

#define C80_MDIO_CONFIG 0x10000
#define C80_MDIO_COMMAND 0x10004
#define C80_MDIO_BUSY 0x80000000U
#define C80_MDIO_EXPECTED_CONFIG 0x45000504U
#define C80_SMI_PHY 29

struct c80_mdio {
	void __iomem *fe;
	u32 commands;
	bool tainted;
};

struct c80_key {
	u16 reg, before, unlocked, after;
	bool saved, dirty, restored;
};

struct c80_switch_snapshot {
	int result;
	u32 stage, cleanup_errors, config_before, config_after, commands;
	struct c80_key id_key, option_key;
	u16 id[2], version[2], option, cpu[4], port[6];
	u32 config_valid, ports_valid, link_mask;
	bool option_valid, tainted;
};

/* Sleepable process context only. Each wait is bounded at 100 ms and
 * leaves local interrupts enabled, allowing the independent PDMA IRQ/NAPI.
 */
static int c80_mdio_wait(struct c80_mdio *p, u32 *value)
{
	return readl_poll_timeout(p->fe + C80_MDIO_COMMAND, *value,
				 !(*value & C80_MDIO_BUSY), 1, 100000);
}

static int c80_mdio_transfer(struct mii_bus *bus, int phy, int reg,
			     u16 value, bool write)
{
	struct c80_mdio *p = bus->priv;
	u32 command, status;
	int ret;

	if ((unsigned int)phy > 31 || (unsigned int)reg > 31)
		return -EINVAL;
	ret = c80_mdio_wait(p, &status);
	if (ret)
		return ret;
	command = (u32)reg << 25 | (u32)phy << 20 | 1U << 16 |
		  (write ? 1U : 2U) << 18 | (write ? value : 0);
	/* The measured U-Boot path clears then starts this command latch. */
	writel(command, p->fe + C80_MDIO_COMMAND);
	writel(command | C80_MDIO_BUSY, p->fe + C80_MDIO_COMMAND);
	p->commands++;
	ret = c80_mdio_wait(p, &status);
	if (ret)
		return ret;
	/* Conservative spacing between SMI latch writes; no clock changes. */
	if (write)
		usleep_range(20, 40);
	return write ? 0 : status & 0xffff;
}

static int c80_mdio_read(struct mii_bus *bus, int phy, int reg)
{
	return c80_mdio_transfer(bus, phy, reg, 0, false);
}

static int c80_mdio_write(struct mii_bus *bus, int phy, int reg, u16 value)
{
	return c80_mdio_transfer(bus, phy, reg, value, true);
}

static int c80_smi_read(struct mii_bus *bus, u16 reg, u16 *value)
{
	int ret;

	ret = __mdiobus_write(bus, C80_SMI_PHY, 31, 0x000e);
	if (ret)
		return ret;
	ret = __mdiobus_write(bus, C80_SMI_PHY, 23, reg);
	if (ret)
		return ret;
	ret = __mdiobus_write(bus, C80_SMI_PHY, 21, 1);
	if (ret)
		return ret;
	ret = __mdiobus_read(bus, C80_SMI_PHY, 25);
	if (ret < 0)
		return ret;
	*value = ret;
	return 0;
}

static int c80_smi_key_write(struct mii_bus *bus, u16 reg, u16 value)
{
	int ret;

	/* Keep even a future accidental caller away from configuration data. */
	if ((reg != 0x13c2 && reg != 0x13c0) || (value && value != 0x249))
		return -EPERM;
	ret = __mdiobus_write(bus, C80_SMI_PHY, 31, 0x000e);
	if (ret)
		return ret;
	ret = __mdiobus_write(bus, C80_SMI_PHY, 23, reg);
	if (ret)
		return ret;
	ret = __mdiobus_write(bus, C80_SMI_PHY, 24, value);
	if (ret)
		return ret;
	return __mdiobus_write(bus, C80_SMI_PHY, 21, 3);
}

static int c80_key_open(struct mii_bus *bus, struct c80_key *key)
{
	int ret;

	ret = c80_smi_read(bus, key->reg, &key->before);
	if (ret)
		return ret;
	key->saved = true;
	if (key->before && key->before != 0x249)
		return -EPERM;
	/* A timed-out write may have reached the ASIC: clean up on every exit. */
	key->dirty = true;
	ret = c80_smi_key_write(bus, key->reg, 0x249);
	if (ret)
		return ret;
	ret = c80_smi_read(bus, key->reg, &key->unlocked);
	if (ret)
		return ret;
	return key->unlocked == 0x249 ? 0 : -EIO;
}

static void c80_key_close(struct mii_bus *bus, struct c80_key *key,
			  u32 *errors, unsigned int shift)
{
	int ret;

	if (!key->dirty)
		return;
	if (c80_smi_key_write(bus, key->reg, key->before))
		*errors |= 1U << shift;
	/* Attempt readback even if the restore write was not acknowledged. */
	ret = c80_smi_read(bus, key->reg, &key->after);
	if (ret)
		*errors |= 2U << shift;
	else if (key->after != key->before)
		*errors |= 4U << shift;
	else {
		key->dirty = false;
		key->restored = true;
	}
}

static void c80_switch_read(struct mii_bus *bus, struct c80_switch_snapshot *s)
{
	static const u16 cpu_registers[] = { 0x1305, 0x1311, 0x1d11, 0x1d41 };
	static const u16 ports[] = { 0, 1, 2, 3, 4, 6 };
	struct c80_mdio *p = bus->priv;
	unsigned int i;
	int ret = 0;

	s->id_key.reg = 0x13c2;
	s->option_key.reg = 0x13c0;
	mutex_lock(&bus->mdio_lock);
	p->commands = 0;
	s->config_before = readl(p->fe + C80_MDIO_CONFIG);
	if (p->tainted) {
		ret = -EUCLEAN;
		goto finish;
	}
	if (s->config_before != C80_MDIO_EXPECTED_CONFIG) {
		ret = -EINVAL;
		goto finish;
	}
	s->stage = 10;
	ret = c80_key_open(bus, &s->id_key);
	if (ret)
		goto cleanup;
	for (i = 0; i < 2; i++) {
		s->stage = 20 + i;
		ret = c80_smi_read(bus, 0x1300, &s->id[i]);
		if (!ret)
			ret = c80_smi_read(bus, 0x1301, &s->version[i]);
		if (ret)
			goto cleanup;
	}
	s->stage = 30;
	c80_key_close(bus, &s->id_key, &s->cleanup_errors, 0);
	if (s->cleanup_errors) {
		ret = -EUCLEAN;
		goto finish;
	}
	if (s->id[0] != 0x6367 || s->id[1] != 0x6367 ||
	    s->version[0] != 0xa0 || s->version[1] != 0xa0) {
		ret = -ENODEV;
		goto finish;
	}
	s->stage = 40;
	ret = c80_key_open(bus, &s->option_key);
	if (ret)
		goto cleanup;
	s->stage = 50;
	ret = c80_smi_read(bus, 0x13c1, &s->option);
	if (ret)
		goto cleanup;
	s->option_valid = true;
	s->stage = 60;
	c80_key_close(bus, &s->option_key, &s->cleanup_errors, 3);
	if (s->cleanup_errors) {
		ret = -EUCLEAN;
		goto finish;
	}
	for (i = 0; i < ARRAY_SIZE(cpu_registers); i++) {
		s->stage = 70 + i;
		ret = c80_smi_read(bus, cpu_registers[i], &s->cpu[i]);
		if (ret)
			goto finish;
		s->config_valid++;
	}
	for (i = 0; i < ARRAY_SIZE(ports); i++) {
		s->stage = 80 + i;
		ret = c80_smi_read(bus, 0x1352 + ports[i], &s->port[i]);
		if (ret)
			goto finish;
		s->ports_valid++;
		if (s->port[i] & 0x10)
			s->link_mask |= 1U << ports[i];
	}
	goto finish;
cleanup:
	/* Both restores are attempted, with at most one bounded write/read each. */
	c80_key_close(bus, &s->option_key, &s->cleanup_errors, 3);
	c80_key_close(bus, &s->id_key, &s->cleanup_errors, 0);
finish:
	s->config_after = readl(p->fe + C80_MDIO_CONFIG);
	if (s->config_before != s->config_after)
		s->cleanup_errors |= 0x40;
	if (s->cleanup_errors) {
		p->tainted = true;
		if (!ret)
			ret = -EUCLEAN;
	}
	s->result = ret;
	s->commands = p->commands;
	s->tainted = p->tainted;
	mutex_unlock(&bus->mdio_lock);
}

ssize_t c80_mdio_snapshot(struct mii_bus *bus, char *buf)
{
	struct c80_switch_snapshot s = {};

	c80_switch_read(bus, &s);
	/* No output or sysfs formatting until all attempted restores complete. */
	return sysfs_emit(buf,
		"C80 Linux MDIO snapshot v1\n"
		"result=%d cleanup_errors=%08x tainted=%u stage=%u commands=%u\n"
		"id=%04x/%04x version=%04x/%04x\n"
		"key13c2=%04x/%04x/%04x saved=%u restored=%u dirty=%u\n"
		"key13c0=%04x/%04x/%04x saved=%u restored=%u dirty=%u\n"
		"option13c1=%04x valid=%u config_valid=%u ports_valid=%u\n"
		"cpu_1305_1311_1d11_1d41=%04x %04x %04x %04x\n"
		"port_status_0_1_2_3_4_6=%04x %04x %04x %04x %04x %04x link_mask=%02x\n"
		"mdio_config=%08x/%08x\n",
		s.result, s.cleanup_errors, s.tainted, s.stage, s.commands,
		s.id[0], s.id[1], s.version[0], s.version[1],
		s.id_key.before, s.id_key.unlocked, s.id_key.after,
		s.id_key.saved, s.id_key.restored, s.id_key.dirty,
		s.option_key.before, s.option_key.unlocked, s.option_key.after,
		s.option_key.saved, s.option_key.restored, s.option_key.dirty,
		s.option, s.option_valid, s.config_valid, s.ports_valid,
		s.cpu[0], s.cpu[1], s.cpu[2], s.cpu[3],
		s.port[0], s.port[1], s.port[2], s.port[3], s.port[4], s.port[5],
		s.link_mask, s.config_before, s.config_after);
}

static void c80_mdio_unregister(void *data)
{
	struct mii_bus *bus = data;

	mdiobus_unregister(bus);
	mdiobus_free(bus);
}

struct mii_bus *c80_mdio_register(struct device *dev, void __iomem *fe)
{
	struct mii_bus *bus;
	struct c80_mdio *p;
	int ret;

	bus = mdiobus_alloc_size(sizeof(*p));
	if (!bus)
		return ERR_PTR(-ENOMEM);
	p = bus->priv;
	p->fe = fe;
	bus->name = "C80 RAM MDIO, inherited configuration";
	strscpy(bus->id, "c80-ram-mdio", MII_BUS_ID_SIZE);
	bus->parent = dev;
	bus->read = c80_mdio_read;
	bus->write = c80_mdio_write;
	/* No auto-probed PHY, reset callback, GPIO, OF child or DSA setup. */
	bus->phy_mask = ~0U;
	ret = mdiobus_register(bus);
	if (ret) {
		mdiobus_free(bus);
		return ERR_PTR(ret);
	}
	ret = devm_add_action_or_reset(dev, c80_mdio_unregister, bus);
	return ret ? ERR_PTR(ret) : bus;
}
