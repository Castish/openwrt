/* SPDX-License-Identifier: GPL-2.0-only
 * Independent RAM-only RTL8367S inherited-HSGMII operations.
 * No analog SerDes/MCU initialization or chip reset is implemented here.
 */
#ifndef C80_RTL8367S_H
#define C80_RTL8367S_H
struct c80_rtl_io {
	void *ctx;
	int (*read)(void *ctx, unsigned int reg, unsigned int *value);
	int (*write)(void *ctx, unsigned int reg, unsigned int value);
};

static int c80_rtl_protected_read(struct c80_rtl_io *io, unsigned int key,
				unsigned int reg, unsigned int *first,
				unsigned int *second)
{
	unsigned int before, check;
	int ret, cleanup = 0;

	ret = io->read(io->ctx, key, &before);
	if (ret)
		return ret;
	if (before)
		return -EINVAL;
	/* Cleanup even if an unlock write timed out after reaching the ASIC. */
	ret = io->write(io->ctx, key, 0x249);
	if (!ret) {
		ret = io->read(io->ctx, key, &check);
		if (!ret && check != 0x249)
			ret = -EIO;
	}
	if (!ret)
		ret = io->read(io->ctx, reg, first);
	if (!ret && second)
		ret = io->read(io->ctx, reg + 1, second);
	if (io->write(io->ctx, key, before))
		cleanup = -EUCLEAN;
	if (io->read(io->ctx, key, &check) || check != before)
		cleanup = -EUCLEAN;
	return cleanup ? cleanup : ret;
}

static int c80_rtl_guard(struct c80_rtl_io *io, unsigned int *id,
			 unsigned int *version)
{
	unsigned int id2, ver2, option, mode, force, sds, eco;
	int ret;

	ret = c80_rtl_protected_read(io, 0x13c2, 0x1300, id, version);
	if (ret)
		return ret;
	ret = c80_rtl_protected_read(io, 0x13c2, 0x1300, &id2, &ver2);
	if (ret)
		return ret;
	if (*id != 0x6367 || id2 != *id || *version != 0xa0 || ver2 != *version)
		return -ENODEV;
	ret = c80_rtl_protected_read(io, 0x13c0, 0x13c1, &option, 0);
	if (ret)
		return ret;
	if (option != 1)
		return -EINVAL;
	ret = io->read(io->ctx, 0x1305, &mode);
	if (!ret)
		ret = io->read(io->ctx, 0x1311, &force);
	if (!ret)
		ret = io->read(io->ctx, 0x1d11, &sds);
	if (!ret)
		ret = io->read(io->ctx, 0x1d41, &eco);
	if (ret)
		return ret;
	if (mode != 0xc0a0 || eco != 0x1f ||
	    !((force == 0x1016 && sds == 0x1f00) ||
	      (force == 0x1006 && sds == 0x1d00)))
		return -EINVAL;
	return 0;
}

static int c80_rtl_link(struct c80_rtl_io *io, bool up)
{
	unsigned int mode, old_force, old_sds, force, sds, check;
	int ret, cleanup = 0;

	ret = io->read(io->ctx, 0x1305, &mode);
	if (!ret)
		ret = io->read(io->ctx, 0x1311, &old_force);
	if (!ret)
		ret = io->read(io->ctx, 0x1d11, &old_sds);
	if (ret)
		return ret;
	if (mode != 0xc0a0 ||
	    !((old_force == 0x1016 && old_sds == 0x1f00) ||
	      (old_force == 0x1006 && old_sds == 0x1d00)))
		return -EINVAL;
	force = up ? 0x1016 : 0x1006;
	sds = up ? 0x1f00 : 0x1d00;
	ret = io->write(io->ctx, 0x1d11, sds);
	if (!ret)
		ret = io->write(io->ctx, 0x1311, force);
	if (!ret) {
		ret = io->read(io->ctx, 0x1d11, &check);
		if (!ret && check != sds)
			ret = -EIO;
	}
	if (!ret) {
		ret = io->read(io->ctx, 0x1311, &check);
		if (!ret && check != force)
			ret = -EIO;
	}
	if (!ret)
		return 0;
	if (io->write(io->ctx, 0x1d11, old_sds))
		cleanup = -EUCLEAN;
	if (io->write(io->ctx, 0x1311, old_force))
		cleanup = -EUCLEAN;
	if (io->read(io->ctx, 0x1d11, &check) || check != old_sds)
		cleanup = -EUCLEAN;
	if (io->read(io->ctx, 0x1311, &check) || check != old_force)
		cleanup = -EUCLEAN;
	return cleanup ? cleanup : ret;
}
#endif
