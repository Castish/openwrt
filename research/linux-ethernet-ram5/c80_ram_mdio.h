/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_RAM_MDIO_H
#define C80_RAM_MDIO_H
#include <linux/types.h>
#include <linux/compiler_types.h>

struct device;
struct mii_bus;

struct mii_bus *c80_mdio_register(struct device *dev, void __iomem *fe);
ssize_t c80_mdio_snapshot(struct mii_bus *bus, char *buf);
#endif
