/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_SECURITY_TYPES_H
#define C80_SECURITY_TYPES_H
#define C80_KEY_STATE 86u
#define C80_KEY_ADD 1u
#define C80_KEY_DEL 2u
#define C80_KEY_AUTHORIZE 3u
#define C80_KEY_UNAUTHORIZE 4u
#define C80_KEY_INSTALL 0u
#define C80_KEY_IDENTICAL 1u
#define C80_KEY_REFRESH_GTK 2u
#define C80_KEY_REFUSE 3u
struct c80_key_request {
    c80_u32 serial,operation,pairwise,index;
    c80_u8 key[16],peer[6];
};
/* CPU-only state. No key, nonce or PN is printed through sysfs. */
struct c80_security_result {
    c80_u32 bmc_live,gtk,ptk,authorized,gtk_index;
    c80_u32 waiting,extension,valid,status,event_bytes;
    c80_u32 key_adds,key_deletes,key_idempotent,authorizations,refused,gtk_refreshes;
    c80_u32 rx_eapol,rx_encrypted,rx_blocked,rx_replay,rx_bad_crypto;
    c80_u32 tx_eapol,tx_encrypted,tx_blocked;
    c80_u8 gtk_key[16],ptk_key[16],assoc_rsn[24];
    c80_u32 assoc_rsn_bytes;
    c80_u64 rx_pn[17];
};
/* Shared by the real MCU worker and the QEMU key backend. hostapd renews
 * GTK on the first station even with periodic rekey disabled. WCID0 never
 * transmits group data in this profile. Allow a changed GTK only before
 * any PTK/authorization; identical live keys must never reset a PN. */
static inline c80_u32 c80_security_add_action(const struct c80_security_result *s,
                                              const struct c80_key_request *q)
{
    const c80_u8 *key=q->pairwise?s->ptk_key:s->gtk_key;c80_u32 i,diff=0;
    if(!(q->pairwise?s->ptk:s->gtk)) return C80_KEY_INSTALL;
    for(i=0;i<16;++i) diff|=key[i]^q->key[i];
    if(!diff && (q->pairwise || q->index==s->gtk_index)) return C80_KEY_IDENTICAL;
    if(!q->pairwise && !s->ptk && !s->authorized) return C80_KEY_REFRESH_GTK;
    return C80_KEY_REFUSE;
}
static inline void c80_secret_clear(void *p,c80_u32 n)
{ volatile c80_u8 *v=p;while(n--) *v++=0; }
#endif
