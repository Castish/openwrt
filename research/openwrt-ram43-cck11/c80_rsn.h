/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_RSN_H
#define C80_RSN_H
/* WPA2-PSK/CCMP only; no PMF, WPA1/TKIP, SAE, PMKID cache or mixed suites. */
static int c80_rsn_valid(const c80_u8 *p,c80_u32 n)
{
    static const c80_u8 fixed[18]={1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,2};
    c80_u32 i;
    if(n!=20 && n!=22) return 0;
    for(i=0;i<18;++i) if(p[i]!=fixed[i]) return 0;
    if(c80_get16(p+18)&~0x003cu) return 0;
    if(n==22 && c80_get16(p+20)) return 0;
    return 1;
}
#endif
