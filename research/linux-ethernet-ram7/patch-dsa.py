#!/usr/bin/env python3
"""Opt-in inherited-HSGMII support for the measured C80 RTL8367S only."""
from pathlib import Path
root=Path(__file__).resolve().parent
p=root/'linux-6.12.113/drivers/net/dsa/realtek/rtl8365mb.c'
t=p.read_text()
if '/* C80 RAM inherited HSGMII */' in t:
    assert t==(root/'rtl8365mb-patched.c').read_text()
else:
    def replace(old,new):
        global t
        assert t.count(old)==1,old[:100]
        t=t.replace(old,new,1)
    replace('#include "rtl83xx.h"', '#include "rtl83xx.h"\n#include "c80_rtl8367s.h"')
    replace('struct rtl8365mb {\n','struct rtl8365mb {\n\tbool c80_inherited;\n')
    anchor='static int rtl8365mb_phy_poll_busy(struct realtek_priv *priv)'
    helper='''/* C80 RAM inherited HSGMII */
static int rtl8365mb_c80_read(void *ctx, unsigned int reg, unsigned int *value)
{
	struct realtek_priv *priv = ctx;
	return regmap_read(priv->map_nolock, reg, value);
}
static int rtl8365mb_c80_write(void *ctx, unsigned int reg, unsigned int value)
{
	struct realtek_priv *priv = ctx;
	return regmap_write(priv->map_nolock, reg, value);
}
static int rtl8365mb_c80_force(struct realtek_priv *priv, bool up)
{
	struct c80_rtl_io io = { priv, rtl8365mb_c80_read, rtl8365mb_c80_write };
	int ret;
	rtl83xx_lock(priv);
	ret = c80_rtl_link(&io, up);
	rtl83xx_unlock(priv);
	return ret;
}

'''
    replace(anchor,helper+anchor)
    replace('config->mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE |', '''if (((struct rtl8365mb *)((struct realtek_priv *)ds->priv)->chip_data)->c80_inherited && port == 6) {
		config->mac_capabilities = MAC_2500FD;
		__set_bit(PHY_INTERFACE_MODE_2500BASEX, config->supported_interfaces);
		return;
	}

	config->mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE |''')
    replace('if (phy_interface_mode_is_rgmii(state->interface)) {', '''if (((struct rtl8365mb *)priv->chip_data)->c80_inherited && port == 6) {
		if (mode != MLO_AN_FIXED || state->interface != PHY_INTERFACE_MODE_2500BASEX)
			dev_err(priv->dev, "C80 CPU port requires fixed 2500base-x\\n");
		return;
	}

	if (phy_interface_mode_is_rgmii(state->interface)) {''')
    old='if (phy_interface_mode_is_rgmii(interface)) {'
    assert t.count(old)==2
    t=t.replace(old,'''if (mb->c80_inherited && port == 6) {
		ret = rtl8365mb_c80_force(priv, false);
		if (ret)
			dev_err(priv->dev, "C80 CPU link down failed: %d\\n", ret);
		return;
	}

	'''+old,1)
    # Second occurrence belongs to link_up after the first was extended.
    start=t.index('static void rtl8365mb_phylink_mac_link_up')
    before=t[:start];after=t[start:]
    after=after.replace(old,'''if (mb->c80_inherited && port == 6) {
		ret = -EINVAL;
		if (interface == PHY_INTERFACE_MODE_2500BASEX && speed == SPEED_2500 &&
		    duplex == DUPLEX_FULL && !tx_pause && !rx_pause)
			ret = rtl8365mb_c80_force(priv, true);
		if (ret)
			dev_err(priv->dev, "C80 CPU link up failed: %d\\n", ret);
		return;
	}

	'''+old,1)
    t=before+after
    old='\tret = rtl8365mb_reset_chip(priv);\n'
    replace(old,'''\tif (mb->c80_inherited) {
		/* Keep the bootloader's measured analog/MCU settings. DSA owns
		 * CPU tags, isolation, STP and PHY management from this point. */
		ret = regmap_update_bits(priv->map, 0x07a8, BIT(0), 0);
		if (!ret)
			ret = regmap_update_bits(priv->map, 0x07a9, 0x07ff, 0);
		if (ret)
			return ret;
		dev_info(priv->dev, "C80 RAM: inherited HSGMII, reset/jam skipped, VLAN filtering disabled\\n");
		goto c80_configure;
	}

'''+old)
    replace('\t/* Set up cascading IRQs */', 'c80_configure:\n\t/* Set up cascading IRQs */')
    replace('ret = rtl8365mb_irq_setup(priv);', 'ret = mb->c80_inherited ? -EOPNOTSUPP : rtl8365mb_irq_setup(priv);')
    replace('\tret = rtl8365mb_get_chip_id_and_ver(priv->map, &chip_id, &chip_ver);', '''\tmb->c80_inherited = of_property_read_bool(priv->dev->of_node,
						 "tplink,c80-ram-inherit-hsgmii");
	if (mb->c80_inherited) {
		struct c80_rtl_io io = { priv, rtl8365mb_c80_read, rtl8365mb_c80_write };
		rtl83xx_lock(priv);
		ret = c80_rtl_guard(&io, &chip_id, &chip_ver);
		rtl83xx_unlock(priv);
	} else {
		ret = rtl8365mb_get_chip_id_and_ver(priv->map, &chip_id, &chip_ver);
	}''')
    p.write_text(t);(root/'rtl8365mb-patched.c').write_text(t)
(p.parent/'c80_rtl8367s.h').write_bytes((root/'c80_rtl8367s.h').read_bytes())
print('C80-only opt-in DSA warm path prepared.')
