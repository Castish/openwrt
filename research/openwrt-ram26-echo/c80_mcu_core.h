/* SPDX-License-Identifier: GPL-2.0-only */
/* Bounded MT7626 MCU/channel/MAC/beacon experiment. No client-data/flash commands.
 * Shared with the native fault model; OS supplies coherent DMA, uncached EMI,
 * MMIO, monotonic time and barriers. Only little-endian ARM/x86 are supported.
 */
#ifndef C80_MCU_CORE_H
#define C80_MCU_CORE_H
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This bring-up core requires a little-endian CPU
#endif
typedef unsigned int c80_u32;
typedef unsigned char c80_u8;
typedef unsigned long long c80_u64;
#define C80_TX_N 128u
#define C80_COMMAND_SLOTS 29u
#define C80_COMMAND_BYTES 1152u
#define C80_NVM_BYTES 1024u
#define C80_NVM_COPY_BYTES 960u
#define C80_RADIO_CRC 0x5c6536a7u /* This user's preserved4KiB RADIO sector. */
#define C80_FRAGMENT_SLOTS 32u
#define C80_SYNC (C80_HIF+0xc1140)
#define C80_RX_N 64u
#define C80_RX_SIZE 1536u
#define C80_AUTH_RING 0x18004350u
#define C80_AUTH_N 32u
#define C80_EMI_SIZE 0x200000u
#define C80_HIF 0x18000000u
#define C80_OWN (C80_HIF+0x7000)
#define C80_GLO (C80_HIF+0x4208)
#define C80_DOWNLOAD_MODE 0x200u /* Actual OEM40308dd0, WPDMA download mode. */
#define C80_MASK (C80_HIF+0x4204)
#define C80_SOURCE (C80_HIF+0x4200)
#define C80_IRQ_RX1 2u /* OEM403087cc RX1 source; only this bit is unmasked. */
#define C80_RESET 0x10212018u
#define C80_DONE 0x80000000u
#define C80_LS0 0x40000000u
#define C80_MAX_POLLS 40000u
#define C80_NVM_WAIT_US 60000000u /* OEM40312678/40312814: attrs.wait_ms=60000. */
#define C80_NVM_POLL_US 1000u
#define C80_DEVINFO_WAIT_US 6000000u /* OEM40261b80/8c: default6000ms. */

struct c80_desc { volatile c80_u32 addr, ctrl, addr1, info; };
struct c80_dma_pool {
    struct c80_desc tx[C80_TX_N], fwdl[C80_TX_N];
    struct c80_desc rx[2][C80_RX_N];
    c80_u8 command[C80_COMMAND_SLOTS][C80_COMMAND_BYTES];
    c80_u8 fragment[C80_FRAGMENT_SLOTS][1024];
    c80_u8 data[2][C80_RX_N][C80_RX_SIZE];
    c80_u8 nvm_payload[4+C80_NVM_BYTES]; /* Not a standalone DMA packet. */
    c80_u8 beacon_body[528]; /* CPU scratch only, copied to unique TX slot. */
    struct c80_desc auth_tx[C80_AUTH_N] __attribute__((aligned(16)));
    c80_u8 auth_header[64] __attribute__((aligned(16)));
    c80_u8 auth_frame[32] __attribute__((aligned(16)));
    c80_u8 assoc_header[64] __attribute__((aligned(16)));
    c80_u8 assoc_frame[48] __attribute__((aligned(16))); /* one pinned36-byte reply */
    c80_u8 diag_header[2][64] __attribute__((aligned(16)));
    c80_u8 diag_frame[2][160] __attribute__((aligned(16))); /* ARP/ICMP, never reused */

};
struct c80_blob { const c80_u8 *data; c80_u32 bytes; };
struct c80_result;
struct c80_io {
    void *context;
    c80_u32 (*read)(void *,c80_u32);
    void (*write)(void *,c80_u32,c80_u32);
    c80_u64 (*time_us)(void *);
    void (*delay_us)(void *,c80_u32);
    void (*dma_order)(void *,int); /* 1:publish before device,0:read device data */
    void (*copy_emi)(void *,c80_u32,const c80_u8 *,c80_u32);
    c80_u32 (*crc_emi)(void *,c80_u32,c80_u32);
    void (*stage)(void *,c80_u32);
    c80_u32 (*irq_arm)(void *,struct c80_result *);
    c80_u32 (*irq_disarm)(void *,struct c80_result *);
    c80_u32 (*nvm_read)(void *,c80_u8 *,c80_u32,c80_u32 *);
    c80_u32 devinfo_test; /* Linux enables the bounded ON/OFF experiment. */
    c80_u32 bss_test; /* OWN/BASIC context lifecycle between DEVINFO ON/OFF. */
    c80_u32 radio_test; /* One channel, bounded MAC ON/listen/OFF lifecycle. */
    c80_u32 beacon_test; /* Bounded30s firmware beacon offload inside radio. */
    c80_u32 watch_test; /* Compare idle radio vs beacon window; read-only HIF watch. */
    c80_u32 rx0_rearm_test; /* Return completed RX0 buffers; bounded64-frame poll budget. */
    c80_u32 beacon_state_test; /* Five stored MAC snapshots + two OEM TSF queries. */
    c80_u32 bss_period_test; /* Match BASIC timing to beacon/SYNC100TU/DTIM1. */
    c80_u32 rx1_rearm_test,management_rx_test; /* Bounded event return and client RX counters. */
    c80_u32 rx1_packet_test; /* Classify RX1 descriptors before MCU event parsing. */
    c80_u32 data_echo_test; /* One ARP and one ICMP response; no netdev/DHCP. */
    c80_u32 assoc_reply_test; /* One STA/WTBL lifecycle + one association response. */
    c80_u32 auth_reply_test; /* At most one open-auth response; no association/data. */
    struct c80_dma_pool *pool;
    c80_u32 dma_base;
};
enum c80_failure {
    C80_OK=0,C80_BAD_FW=1,C80_BAD_AON=2,C80_BAD_ID=3,C80_STALE=4,
    C80_BAD_TIMER=5,C80_BOOT_CONTROL=6,C80_READY_TIMEOUT=7,C80_OWN_TIMEOUT=8,
    C80_BAD_DMA=9,C80_MAIN_CRC=10,C80_RINGS_CONFIGURED=11,C80_TX_TIMEOUT=12,
    C80_RX_TIMEOUT=13,C80_RX_BAD=14,C80_SEMAPHORE=15,C80_RESTORE=16,
    C80_RING_PROGRAM=17,C80_DOWNLOAD_STATUS=18,C80_FWDL_TIMEOUT=19,
    C80_PATCH_NOT_READY=20,C80_BAD_SYNC=21,C80_MAIN_NOT_READY=22,C80_MODE_REFUSED=23,
    C80_QUERY_BAD=24,C80_IRQ_NOT_SEEN=25,C80_IRQ_BAD=26,
    C80_NVM_BAD_SOURCE=27,C80_NVM_SET_REJECTED=28,C80_NVM_BAD_REPLY=29,C80_NVM_MISMATCH=30,
    C80_DEVINFO_BAD_MAC=31,C80_DEVINFO_REJECTED=32,C80_DEVINFO_BAD_REPLY=33,
    C80_BSS_BAD_STATE=34,C80_BSS_REJECTED=35,C80_BSS_BAD_REPLY=36,
    C80_RADIO_BAD_STATE=37,C80_RADIO_REJECTED=38,C80_RADIO_BAD_REPLY=39,
    C80_RADIO_RX_BAD=40,
    C80_BEACON_BAD_STATE=41,C80_BEACON_REJECTED=42,C80_BEACON_BAD_REPLY=43,C80_HIF_CHANGED=44,C80_RX0_RETURN_FAILED=45,C80_TSF_BAD_REPLY=46,C80_STATE_BAD_PREREQ=47,C80_BSS_PERIOD_BAD_PREREQ=48,C80_RX1_RETURN_FAILED=49,C80_RX1_BAD_PREREQ=50,C80_MGMT_BAD_PREREQ=51,C80_AUTH_BAD_PREREQ=52,C80_AUTH_RING_BASELINE=53,C80_AUTH_RING_PROGRAM=54,C80_AUTH_PUBLISH=55,C80_AUTH_TIMEOUT=56,C80_AUTH_BAD_DESC=57,C80_RX1_NOTIFY_BAD=58,C80_ASSOC_BAD_PREREQ=59,C80_STA_BAD_REPLY=60,C80_STA_REJECTED=61,C80_ASSOC_PUBLISH=62,C80_ASSOC_TIMEOUT=63,C80_ASSOC_BAD_DESC=64,C80_DATA_BAD_PREREQ=65,C80_DATA_PUBLISH=66,C80_DATA_BAD_DESC=67,C80_DATA_TIMEOUT=68,
    C80_CRITICAL_RESET=80,C80_CRITICAL_DMA=81
};
/* Non-atomic observations of already-used, readable HIF registers. No
 * selector/acknowledgement/ownership/config writes are performed by the watch. */
struct c80_hif_sample {
    c80_u32 glo,own,sync,source,mask,tx_cpu,tx_dma,rx0_dma,rx1_dma;
};
struct c80_watch_window {
    c80_u32 started,complete,elapsed_us,samples,last_good_us,fault_bits;
    struct c80_hif_sample before,last;
};
struct c80_management_counts {
    c80_u32 headers,subtype[16],short_header,bad_fc,peer_bad,protected_ordered,fragments,to_us;
    c80_u32 probe_eligible,probe_test_ssid,probe_wildcard,probe_other_ssid,probe_short_ssid;
    c80_u32 auth_to_us,auth_open_request,auth_other,assoc_to_us,reassoc_to_us,deauth_to_us,disassoc_to_us;
};
struct c80_result {
    c80_u32 phase,primary,cleanup,critical,ready,own_before,own_last,own_sent;
    c80_u32 glo_before,glo_after,mask_before,mask_after,source_after;
    c80_u32 controls_before[3],controls_after[3],aon_before[10],aon_after[10];
    c80_u32 rings_before[4][4],rings_after[4][4];
    c80_u32 main_crc[2],tx_submitted,tx_completed,rx_packets,rx_ignored;
    c80_u32 get_valid,get_status,release_valid,release_status,rx_bad_ctrl;
    c80_u32 last_event_len,last_event_id,last_event_seq,last_packet_id;
    c80_u32 dma_started,dma_idle,mcu_released,mcu_stopped,controls_touched;
    c80_u32 rings_touched,dma_cfg_touched,rx_next[2];
    c80_u32 cleanup_flags,controls_owned_bad,controls_other_changed;
    c80_u32 control_diff[3],rings_restore_bad;
    c80_u32 command_submitted,command_completed,fwdl_submitted,fwdl_completed;
    c80_u32 sequence,last_event_status,sem_held,release_attempted;
    c80_u32 patch_address_valid,patch_address_status,patch_finish_valid,patch_finish_status;
    c80_u32 patch_bytes,patch_chunks,patch_ready_valid,patch_ready_status,patch_uploaded;
    c80_u32 main_attempted,main_region_index,main_regions_complete,main_bytes,main_chunks;
    c80_u32 main_region_valid,main_region_status[3],main_region_bytes[3],main_region_chunks[3];
    c80_u32 main_start_attempted,main_start_valid,main_start_status,main_ready;
    c80_u32 main_sync_before,main_sync_after;
    c80_u32 download_mode_checked,download_enable_glo,download_last_glo;
    c80_u32 failure_snapshot,failure_phase,failure_ring,failure_slot;
    c80_u32 failure_cpu,failure_dma,failure_desc[4];
    c80_u32 failure_glo,failure_mask,failure_source,failure_sync,failure_own;
    c80_u32 runtime_glo_before,runtime_glo_after,last_event_ext;
    c80_u32 counter_query_attempted,counter_query_valid,counter_category,counter_count,counter_value;
    c80_u32 mask_main_ready,mask_runtime,mask_cleanup_entry,mask_first_zero,mask_after_stop,mask_before_final_zero,mask_zero_writes;
    c80_u32 irq_attempted,irq_armed,irq_entries,irq_events,irq_unexpected,irq_faults;
    c80_u32 irq_mask_before,irq_mask_enable,irq_mask_after;
    c80_u32 irq_source_before,irq_source_cleared,irq_source_seen,irq_source_after;
    c80_u32 irq_ack_writes,irq_cpu_started,irq_cpu_stopped;
    c80_u32 nvm_attempted,nvm_valid,nvm_radio_crc,nvm_raw_crc,nvm_upload_crc;
    c80_u32 nvm_set_attempted,nvm_set_valid,nvm_set_status;
    c80_u32 nvm_get_attempted,nvm_get_valid,nvm_get_source,nvm_get_format;
    c80_u32 nvm_get_offset,nvm_get_count,nvm_get_crc,nvm_get_ext,nvm_equal;
    c80_u32 nvm_mismatch_valid,nvm_mismatch_offset;
    c80_u32 nvm_set_wait_us,nvm_set_polls,nvm_get_wait_us,nvm_get_polls;
    c80_u32 nvm_wait_clock_backwards;
    c80_u32 nvm_get_padding,nvm_compared;
    c80_u32 devinfo_mac_valid,devinfo_attempted[2],devinfo_valid[2];
    c80_u32 devinfo_status[2],devinfo_ext[2],devinfo_ownmac[2],devinfo_count[2];
    c80_u32 devinfo_complete,devinfo_wait_us[2],devinfo_polls[2];
    c80_u32 devinfo_event_bytes[2],devinfo_dma_bytes[2],devinfo_tail_bytes[2];
    c80_u32 devinfo_base_read[2],devinfo_echo[2];
    c80_u32 bss_attempted[2],bss_valid[2],bss_status[2],bss_ext[2];
    c80_u32 bss_index[2],bss_count[2],bss_event_bytes[2],bss_dma_bytes[2];
    c80_u32 bss_tail_bytes[2],bss_base_read[2],bss_echo[2],bss_wait_us[2],bss_polls[2];
    c80_u32 bss_complete,bss_period[2],bss_dtim[2];
    c80_u32 radio_attempted[5],radio_valid[5],radio_status[5],radio_ext[5],radio_echo[5];
    c80_u32 radio_event_bytes[5],radio_dma_bytes[5],radio_wait_us[5],radio_polls[5];
    c80_u32 radio_complete,radio_listen_started,radio_listen_us,radio_listen_polls;
    c80_u32 radio_rx_packets,radio_rx_bytes,radio_rx_types[8],radio_rx_bad;
    c80_u32 radio_raw_frames,radio_beacon_headers,radio_rx_translated,radio_rx_full;
    c80_u32 radio_first_dw0,radio_first_dw1,radio_first_valid;
    c80_u32 beacon_attempted[4],beacon_valid[4],beacon_status[4],beacon_ext[4],beacon_echo[4];
    c80_u32 beacon_index[4],beacon_count[4],beacon_base_read[4],beacon_event_bytes[4],beacon_dma_bytes[4],beacon_tail_bytes[4];
    c80_u32 beacon_wait_us[4],beacon_polls[4],beacon_complete;
    c80_u32 beacon_window_started,beacon_window_us,beacon_window_polls;
    struct c80_watch_window watch[2]; /* 0 no beacon; 1 beacon enabled. */
    c80_u32 watch_fault_phase;
    c80_u32 rx0_rearmed,rx0_publishes,rx0_last_cpu,rx0_readback,rx0_budget_yields;
    c80_u32 state_mask,state_guard_fault,state_phase[5],state_allones[5],state_regs[5][12];
    c80_u64 state_us[5];
    c80_u32 tsf_attempted[2],tsf_valid[2],tsf_category[2],tsf_ext[2],tsf_low[2],tsf_high[2];
    c80_u32 tsf_event_bytes[2],tsf_dma_bytes[2],tsf_wait_us[2],tsf_polls[2],tsf_delta_valid;
    c80_u64 tsf_observed_us[2],tsf_delta_us;
    c80_u32 rx1_packets,rx1_rearmed,rx1_publishes,rx1_last_cpu,rx1_readback,rx1_budget_yields;
    c80_u32 rx1_unmatched,rx1_short,rx1_meta_valid,rx1_meta_phase,rx1_meta_pid,rx1_meta_eid;
    c80_u32 rx1_meta_seq,rx1_meta_ext,rx1_meta_event_bytes,rx1_meta_dma_bytes;
    c80_u32 auth_ring_before[4],auth_ring_after[4],auth_ring_saved,auth_ring_touched,auth_ring_programmed,auth_ring_restore_bad;
    c80_u32 auth_captured,auth_duplicate,auth_late,auth_submitted,auth_dma_done,auth_polls,auth_wait_us,auth_cpu_readback,auth_dma_index,auth_ctrl;
    c80_u32 auth_same_peer_assoc,auth_pre_base,auth_pre_count;
    c80_u32 rx1_type[8],rx1_non_event,rx1_unknown,rx1_last_type,rx1_last_bytes,rx1_last_dw0;
    c80_u32 txfree_reports,txfree_valid,txfree_bad,txfree_other,txfree_tokens,txfree_ours;
    c80_u32 txfree_foreign,txfree_before_submit,txfree_duplicate,auth_token_returned;
    c80_u32 txfree_dw0,txfree_dw1,txfree_bytes,txfree_report_type,txfree_count,txfree_version;
    c80_u64 auth_submit_us,assoc_submit_us,assoc_window_start_us;
    c80_u32 assoc_captured,assoc_duplicate,assoc_late,assoc_request_bad,assoc_request_cap,assoc_listen,assoc_rate_mask;
    c80_u32 assoc_submitted,assoc_dma_done,assoc_token_returned,assoc_free_before,assoc_free_duplicate;
    c80_u32 assoc_ctrl,assoc_cpu_readback,assoc_dma_index,assoc_wait_us,assoc_polls,assoc_pre_base,assoc_pre_count;
    c80_u32 assoc_data_candidates,assoc_null_candidates,assoc_complete;
    c80_u32 sta_waiting,sta_attempted[2],sta_valid[2],sta_status[2],sta_echo[2],sta_ext[2];
    c80_u32 sta_event_bytes[2],sta_dma_bytes[2],sta_tail[2],sta_wait_us[2],sta_polls[2];
    c80_u32 sta_meta_valid[2],sta_meta_bss[2],sta_meta_wcid[2],sta_meta_count[2],sta_meta_muar[2];
    c80_u32 data_seen,data_raw,data_translated,data_bad_length,data_bad_status,data_wrong_peer,data_bad_format,data_bad_llc;
    c80_u32 data_arp,data_arp_target,data_ipv4,data_icmp,data_dhcp_candidates,data_other,data_bad_protocol,data_bad_checksum,data_late;
    c80_u32 data_last_rxd1,data_last_rxd2,data_last_fc,data_last_ethertype;
    c80_u32 diag_captured[2],diag_duplicate[2],diag_bytes[2],diag_submitted[2],diag_dma_done[2],diag_token_returned[2];
    c80_u32 diag_early[2],diag_dup_free[2],diag_slot[2],diag_cpu[2],diag_dma[2],diag_ctrl[2],diag_wait_us[2],diag_polls[2],diag_submissions;
    c80_u64 diag_submit_us[2];
    struct c80_management_counts management[2]; /* control38, beacon37; no packet/address saved. */


};
#define C80_CLEANUP_CONTROL 1u
#define C80_CLEANUP_GLO 2u
#define C80_CLEANUP_MASK 4u
#define C80_CLEANUP_RING 8u
static const c80_u32 c80_aon_regs[10]={0x10000220,0x10000228,0x10000230,
    0x10000238,0x10000370,0x10006000,0x10006608,0x1000660c,0x10006610,C80_RESET};
static const c80_u32 c80_controls[3]={0x18002150,0x18001130,0x10210000};
static const c80_u32 c80_control_masks[3]={0x208001,1,12};
static const c80_u32 c80_ring_regs[4]={0x180043f0,0x18004400,0x18004410,0x18004330};
static const c80_u32 c80_blob_sizes[6]={72096,169240,395008,119036,1838,25808};
static const c80_u32 c80_blob_crcs[6]={0x2ede9294,0x4e2c264c,0x10efafc7,0x9d2bbb46,0xce747ab9,0x92c09901};
static const c80_u32 c80_blob_offsets[4]={0,0x43000,0x75000,0x146800};

static c80_u32 c80_crc(const c80_u8 *p,c80_u32 size)
{
    c80_u32 crc=~0u,i;
    while(size--) { crc^=*p++; for(i=0;i<8;++i) crc=(crc>>1)^(0xedb88320u&-(crc&1)); }
    return ~crc;
}
static c80_u32 c80_read(struct c80_io *io,c80_u32 reg)
{ return io->read(io->context,reg); }
static void c80_write(struct c80_io *io,c80_u32 reg,c80_u32 value)
{ io->write(io->context,reg,value); }
static void c80_stage(struct c80_io *io,struct c80_result *r,c80_u32 phase)
{ r->phase=phase; if(io->stage) io->stage(io->context,phase); }
/* The OS serializes these helpers with a raw IRQ-safe lock. The hard IRQ
 * has no waits, allocation, descriptor access or pool lifetime dependency.
 * The CPU IRQ is one-shot too, including on an unexpected/invalid source.
 * Failure bits:1 mask readback,2 invalid source,4 stale RX1,8 unexpected,
 *16 premature/repeated entry. No other W1C source bits are acknowledged. */
static c80_u32 c80_irq_prepare(struct c80_io *io,struct c80_result *r)
{
    r->irq_attempted=1; r->irq_mask_before=c80_read(io,C80_MASK);
    if(r->irq_mask_before==0xffffffffu) { r->irq_faults|=1; return C80_IRQ_BAD; }
    c80_write(io,C80_MASK,0); r->irq_mask_after=c80_read(io,C80_MASK);
    if(r->irq_mask_after) { r->irq_faults|=1; return C80_IRQ_BAD; }
    r->irq_source_before=c80_read(io,C80_SOURCE);
    if(r->irq_source_before==0xffffffffu) { r->irq_faults|=2; return C80_IRQ_BAD; }
    if(r->irq_source_before&C80_IRQ_RX1) {
        c80_write(io,C80_SOURCE,C80_IRQ_RX1); ++r->irq_ack_writes;
    }
    r->irq_source_cleared=c80_read(io,C80_SOURCE);
    if(r->irq_source_cleared==0xffffffffu) { r->irq_faults|=2; return C80_IRQ_BAD; }
    if(r->irq_source_cleared&C80_IRQ_RX1) { r->irq_faults|=4; return C80_IRQ_BAD; }
    r->irq_armed=1; return 0;
}
static c80_u32 c80_irq_unmask(struct c80_io *io,struct c80_result *r)
{
    if(!r->irq_armed || r->irq_entries) { r->irq_faults|=16; return C80_IRQ_BAD; }
    c80_write(io,C80_MASK,C80_IRQ_RX1);
    r->irq_mask_enable=c80_read(io,C80_MASK);
    if(r->irq_mask_enable!=C80_IRQ_RX1) { r->irq_faults|=1; return C80_IRQ_BAD; }
    return 0;
}
static void c80_irq_event(struct c80_io *io,struct c80_result *r)
{
    c80_u32 was_armed=r->irq_armed;
    ++r->irq_entries; r->irq_armed=0;
    r->irq_source_seen=c80_read(io,C80_SOURCE);
    c80_write(io,C80_MASK,0); r->irq_mask_after=c80_read(io,C80_MASK);
    if(r->irq_mask_after) r->irq_faults|=1;
    if(!was_armed || r->irq_entries!=1) r->irq_faults|=16;
    if(r->irq_source_seen==0xffffffffu) { r->irq_faults|=2; return; }
    if(was_armed && (r->irq_source_seen&C80_IRQ_RX1)) {
        ++r->irq_events;
        c80_write(io,C80_SOURCE,C80_IRQ_RX1); ++r->irq_ack_writes;
        r->irq_source_after=c80_read(io,C80_SOURCE);
        if(r->irq_source_after==0xffffffffu) r->irq_faults|=2;
    } else { ++r->irq_unexpected; r->irq_faults|=8; }
}
static c80_u32 c80_irq_stop(struct c80_io *io,struct c80_result *r)
{
    r->irq_armed=0;
    c80_write(io,C80_MASK,0); r->irq_mask_after=c80_read(io,C80_MASK);
    if(r->irq_mask_after) r->irq_faults|=1;
    return r->irq_faults?C80_IRQ_BAD:r->irq_events?0:C80_IRQ_NOT_SEEN;
}
static int c80_poll(struct c80_io *io,c80_u32 reg,c80_u32 mask,c80_u32 value,
                    c80_u32 timeout,c80_u32 *last)
{
    c80_u64 start=io->time_us(io->context),now; c80_u32 i,v;
    for(i=0;i<C80_MAX_POLLS;++i) {
        v=c80_read(io,reg); if(last) *last=v;
        if(v!=0xffffffffu && (v&mask)==value) return 1;
        now=io->time_us(io->context);
        if(now<start || now-start>=timeout) return 0;
        io->delay_us(io->context,50);
    }
    return 0;
}
static c80_u32 c80_dma_address(struct c80_io *io,const volatile void *p)
{ return io->dma_base+(c80_u32)((const volatile c80_u8 *)p-(const volatile c80_u8 *)io->pool); }
static void c80_put16(c80_u8 *p,c80_u32 v) { p[0]=v; p[1]=v>>8; }
static void c80_put32(c80_u8 *p,c80_u32 v)
{ c80_put16(p,v); c80_put16(p+2,v>>16); }
static c80_u32 c80_get16(const c80_u8 *p) { return p[0]|((c80_u32)p[1]<<8); }
static c80_u32 c80_get32(const c80_u8 *p) { return c80_get16(p)|(c80_get16(p+2)<<16); }
/* Exact wire headers reconstructed by executing OEM4026249c. Scatter uses
 * PQIDf800 and packet format3; ordinary commands PQID8000/format2.
 * Payload/packet storage is coherent, never reused while hardware owns it. */
static c80_u32 c80_command(c80_u8 *p,c80_u32 cid,const c80_u8 *body,
                            c80_u32 bytes,c80_u32 sequence)
{
    c80_u32 i,n=64+bytes,scatter=cid==0xee;
    for(i=0;i<n;++i) p[i]=0;
    c80_put32(p,(scatter?0xf8000000:0x80000000)|n);
    c80_put32(p+4,scatter?0x0300a000:0x0200a000);
    c80_put16(p+32,32+bytes); c80_put16(p+34,scatter?0xf800:0x8000);
    p[36]=cid; p[37]=0xa0; p[38]=3; p[39]=sequence;
    /* Exact OEM40314588/4026249c runtime GET: query0, ext3c, extACK1. */
    if(cid==0xed) { p[38]=0; p[41]=0x3c; p[43]=1; }
    for(i=0;i<bytes;++i) p[64+i]=body[i];
    return n;
}
/* Bounded header candidates only. No FCS validation, peer address retention,
 * packet copying, management response or association implementation. */
static int c80_mac_equal(const c80_u8 *a,const c80_u8 *b)
{ c80_u32 i; for(i=0;i<6;++i) if(a[i]!=b[i]) return 0; return 1; }
static int c80_mac_broadcast(const c80_u8 *a)
{ c80_u32 i; for(i=0;i<6;++i) if(a[i]!=255) return 0; return 1; }
/* Exact OEM403199fc CCK1/unassociated-auth TXD, then4031a5b4 TXP.
 * One host frame and header are pinned until MCU stop AND DMA idle, even
 * after descriptor DONE. No TX token reuse or RF/ACK completion claim. */
static void c80_auth_capture(struct c80_io *io,struct c80_result *r,const c80_u8 *peer)
{
    static const c80_u8 txd[32]={0x3e,0,0,0x40,0,0xcc,0,0,0,0,0,0xa0,0,0x38,0,0,
        0,0,0,0,0,0x20,0,0,4,0,0,0,0,0xc0,0x0b,0};
    c80_u8 *f=io->pool->auth_frame,*h=io->pool->auth_header;c80_u32 i;
    if(!io->auth_reply_test || r->phase!=37 || !r->auth_ring_programmed) return;
    if(r->auth_captured) { ++r->auth_duplicate; return; }
    if(r->watch[1].elapsed_us>29000000) { ++r->auth_late; return; }
    if(!r->nvm_equal || !r->devinfo_mac_valid || !r->bss_valid[0] || r->bss_status[0] ||
       !r->radio_valid[3] || r->radio_status[3] || !r->beacon_valid[1] || r->beacon_status[1]) return;
    for(i=0;i<32;++i) f[i]=0;
    c80_put16(f,0x00b0); c80_put16(f+2,304); /* actual402adc78 CCK1/14B ACK duration */
    for(i=0;i<6;++i) { f[4+i]=peer[i];f[10+i]=f[16+i]=io->pool->nvm_payload[8+i]; }
    c80_put16(f+26,2); /* algorithm0, transaction2, success0; seq-control0 */
    for(i=0;i<64;++i) h[i]=i<32?txd[i]:0;
    c80_put16(h+32,0x8000); /* unique token0, valid; no reuse this boot */
    c80_put32(h+40,c80_dma_address(io,f));c80_put16(h+44,0x801e); /*30B,last */
    r->auth_captured=1;
}
static c80_u32 c80_auth_poll(struct c80_io *io,struct c80_result *r)
{
    struct c80_desc *d=&io->pool->auth_tx[0];c80_u64 now;
    if(!io->auth_reply_test || !r->auth_captured || r->auth_dma_done) return 0;
    if(!r->auth_ring_programmed || r->phase!=37) return C80_AUTH_BAD_PREREQ;
    now=io->time_us(io->context);
    if(!r->auth_submitted) {
        r->auth_pre_base=c80_read(io,C80_AUTH_RING);r->auth_pre_count=c80_read(io,C80_AUTH_RING+4);
        if(r->auth_pre_base!=c80_dma_address(io,io->pool->auth_tx) || r->auth_pre_count!=C80_AUTH_N ||
           c80_read(io,C80_AUTH_RING+8) || c80_read(io,C80_AUTH_RING+12)) return C80_AUTH_BAD_DESC;
        d->addr=c80_dma_address(io,io->pool->auth_header);d->addr1=c80_dma_address(io,io->pool->auth_frame);d->info=0;
        d->ctrl=C80_LS0|(64u<<16);io->dma_order(io->context,1);
        r->auth_submitted=1;r->auth_submit_us=now;
        c80_write(io,C80_AUTH_RING+8,1);r->auth_cpu_readback=c80_read(io,C80_AUTH_RING+8);
        if(r->auth_cpu_readback!=1) return C80_AUTH_PUBLISH;
    }
    if(now<r->auth_submit_us) return C80_BAD_TIMER;
    r->auth_wait_us=now-r->auth_submit_us>0xffffffffu?0xffffffffu:(c80_u32)(now-r->auth_submit_us);++r->auth_polls;
    r->auth_ctrl=d->ctrl;r->auth_dma_index=c80_read(io,C80_AUTH_RING+12);
    if(r->auth_dma_index>1 || (r->auth_ctrl&~C80_DONE)!=(C80_LS0|(64u<<16)) ||
       d->addr!=c80_dma_address(io,io->pool->auth_header) || d->addr1!=c80_dma_address(io,io->pool->auth_frame) || d->info)
        return C80_AUTH_BAD_DESC;
    if((r->auth_ctrl&C80_DONE) && r->auth_dma_index==1) {
        io->dma_order(io->context,0);r->auth_dma_done=1;return 0;
    }
    if(r->auth_wait_us>=1000000) return C80_AUTH_TIMEOUT;
    return 0;
}
/* A single bounded legacy/open association candidate. Parse only mandatory
 * first SSID and Supported Rates IEs, never assume trailing FCS is stripped. */
static void c80_assoc_capture(struct c80_io *io,struct c80_result *r,const c80_u8 *p,c80_u32 bytes)
{
    static const c80_u8 ssid[9]={'C','8','0','-','R','A','M','1','6'};
    static const c80_u8 txd[32]={0x44,0x00,0x00,0x40,0x01,0xcc,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x01,0x00};
    c80_u32 i,pos,len,rate,mask=0,fc;c80_u64 now;c80_u8 *f=io->pool->assoc_frame,*h=io->pool->assoc_header;
    if(!io->assoc_reply_test || r->phase!=37 || !r->auth_submitted || !r->auth_dma_done || bytes<28) return;
    fc=c80_get16(p);
    if((fc&0xff) || (fc&0xc700) || (p[22]&15) ||
       !c80_mac_equal(p+4,io->pool->nvm_payload+8) || !c80_mac_equal(p+16,p+4) ||
       !c80_mac_equal(p+10,io->pool->auth_frame+4)) return;
    if(r->assoc_captured) { ++r->assoc_duplicate;return; }
    now=io->time_us(io->context);
    if(now<r->assoc_window_start_us || now-r->assoc_window_start_us>28000000) { ++r->assoc_late;return; }
    if(!r->auth_ring_programmed || !r->nvm_equal || !r->devinfo_mac_valid || !r->bss_valid[0] || r->bss_status[0] ||
       !r->radio_valid[3] || r->radio_status[3] || !r->beacon_valid[1] || r->beacon_status[1]) return;
    r->assoc_request_cap=c80_get16(p+24);r->assoc_listen=c80_get16(p+26);
    if((r->assoc_request_cap&0x13)!=1 || !r->assoc_listen) { ++r->assoc_request_bad;return; }
    if(bytes<39 || p[28]!=0 || p[29]!=9) { ++r->assoc_request_bad;return; }
    for(i=0;i<9;++i) if(p[30+i]!=ssid[i]) { ++r->assoc_request_bad;return; }
    pos=39;
    if(bytes-pos<2 || p[pos]!=1 || !(len=p[pos+1]) || len>8 || len>bytes-pos-2) { ++r->assoc_request_bad;return; }
    for(i=0;i<len;++i) {
        rate=p[pos+2+i]&127;
        if(rate==2) mask|=1;else if(rate==4) mask|=2;else if(rate==11) mask|=4;else if(rate==22) mask|=8;
    }
    r->assoc_rate_mask=mask;
    if(mask!=15) { ++r->assoc_request_bad;return; }
    for(i=0;i<48;++i) f[i]=0;
    c80_put16(f,0x10);c80_put16(f+2,304);c80_put16(f+22,16);
    for(i=0;i<6;++i) { f[4+i]=p[10+i];f[10+i]=f[16+i]=io->pool->nvm_payload[8+i]; }
    c80_put16(f+24,1);c80_put16(f+28,0xc001); /* ESS/open, success0, AID1 */
    f[30]=1;f[31]=4;f[32]=0x82;f[33]=0x84;f[34]=0x8b;f[35]=0x96;
    for(i=0;i<64;++i) h[i]=i<32?txd[i]:0;
    c80_put16(h+32,0x8001);c80_put32(h+40,c80_dma_address(io,f));c80_put16(h+44,0x8024);
    r->assoc_captured=1;
}
static void c80_assoc_data_observe(struct c80_io *io,struct c80_result *r,const c80_u8 *p,c80_u32 bytes)
{
    c80_u32 fc,sub,header;
    if(!io->assoc_reply_test || r->phase!=37 || !r->assoc_submitted || bytes<24) return;
    fc=c80_get16(p);sub=(fc>>4)&15;header=(sub&8)?26:24;
    if((fc&15)!=8 || (fc&0xc700)!=0x100 || (p[22]&15) || bytes<header ||
       !c80_mac_equal(p+4,io->pool->nvm_payload+8) || !c80_mac_equal(p+10,io->pool->auth_frame+4)) return;
    if(sub==4 || sub==12) ++r->assoc_null_candidates;
    else if(bytes>header) ++r->assoc_data_candidates;
}

/* Bounded diagnostic endpoints, not a network interface or general IP stack.
 * Decode only the pinned open peer after STA/association success. Error/length
 * checks precede protocol reads. Only response DMA buffers retain addresses;
 * result/sysfs contain counters, never packet content or learned addresses. */
static c80_u32 c80_be16(const c80_u8 *p) { return ((c80_u32)p[0]<<8)|p[1]; }
static void c80_setbe16(c80_u8 *p,c80_u32 v) { p[0]=v>>8;p[1]=v; }
static c80_u32 c80_sum16(const c80_u8 *p,c80_u32 n)
{
    c80_u32 sum=0;
    while(n>=2) { sum+=c80_be16(p);p+=2;n-=2; }
    if(n) sum+=(c80_u32)p[0]<<8;
    while(sum>>16) sum=(sum&65535)+(sum>>16);
    return (~sum)&65535;
}
static c80_u32 c80_ip_equal(const c80_u8 *p,c80_u32 last)
{ return p[0]==192 && p[1]==168 && p[2]==2 && p[3]==last; }
static void c80_data_frame(struct c80_io *io,struct c80_result *r,c80_u32 kind,
                            const c80_u8 *payload,c80_u32 n)
{
    static const c80_u8 txd[32]={0x5c,0x00,0x00,0x40,0x01,0xcc,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x20,0x00};
    c80_u8 *f=io->pool->diag_frame[kind],*h=io->pool->diag_header[kind];c80_u32 i,bytes;
    for(i=0;i<160;++i) f[i]=0;
    c80_put16(f,0x0208);c80_put16(f+2,304);c80_put16(f+22,(kind+2)<<4);
    for(i=0;i<6;++i) { f[4+i]=io->pool->auth_frame[4+i];f[10+i]=f[16+i]=io->pool->nvm_payload[8+i]; }
    f[24]=f[25]=0xaa;f[26]=3;f[30]=8;f[31]=kind?0:6;
    if(!kind) {
        c80_u8 *arp=f+32;c80_setbe16(arp,1);c80_setbe16(arp+2,0x800);arp[4]=6;arp[5]=4;c80_setbe16(arp+6,2);
        for(i=0;i<6;++i) { arp[8+i]=f[10+i];arp[18+i]=f[4+i]; }
        arp[14]=arp[24]=192;arp[15]=arp[25]=168;arp[16]=arp[26]=2;arp[17]=1;arp[27]=2;bytes=60;
    } else {
        c80_u8 *ip=f+32,*icmp=f+52;ip[0]=0x45;c80_setbe16(ip+2,20+n);c80_setbe16(ip+4,1);ip[8]=64;ip[9]=1;
        ip[12]=ip[16]=192;ip[13]=ip[17]=168;ip[14]=ip[18]=2;ip[15]=1;ip[19]=2;
        for(i=0;i<n;++i) icmp[i]=payload[i];
        icmp[0]=0;icmp[2]=icmp[3]=0;c80_setbe16(icmp+2,c80_sum16(icmp,n));c80_setbe16(ip+10,c80_sum16(ip,20));bytes=52+n;
    }
    for(i=0;i<64;++i) h[i]=i<32?txd[i]:0;
    c80_put16(h,32+bytes);c80_put16(h+32,0x8002+kind);c80_put32(h+40,c80_dma_address(io,f));c80_put16(h+44,0x8000|bytes);
    r->diag_bytes[kind]=bytes;r->diag_captured[kind]=1;
}
static void c80_data_receive(struct c80_io *io,struct c80_result *r,const c80_u8 *v,
                              c80_u32 total,c80_u32 offset)
{
    const c80_u8 *p,*da,*sa,*payload,*peer=io->pool->auth_frame+4,*own=io->pool->nvm_payload+8;
    c80_u32 bytes,fc,sub,seq,qos=0,type,header,n; c80_u64 now;
    if(!io->data_echo_test || r->phase!=37 || !r->assoc_submitted || !r->assoc_dma_done ||
       !r->sta_valid[0] || r->sta_status[0] || r->sta_attempted[1]) return;
    if(total<16 || total>C80_RX_SIZE || offset<16 || offset>total) { ++r->data_bad_length;return; }
    bytes=total-offset;p=v+offset;
    if(v[6]&0x80) {
        ++r->data_translated;
        if(!(v[3]&0x10) || offset<32 || bytes<14) { ++r->data_bad_length;return; }
        fc=c80_get16(v+16);seq=c80_get16(v+24);qos=c80_get16(v+26);
        if(!c80_mac_equal(v+18,peer)) { ++r->data_wrong_peer;return; }
        da=p;sa=p+6;payload=p+14;n=bytes-14;type=c80_be16(p+12);
    } else {
        if(bytes<2) { ++r->data_bad_length;return; }
        fc=c80_get16(p);sub=(fc>>4)&15;
        if((fc&15)!=8 || (sub!=0 && sub!=8)) return;
        ++r->data_raw;header=sub==8?26:24;
        if(bytes<header+8) { ++r->data_bad_length;return; }
        if(!c80_mac_equal(p+4,own)) { ++r->data_wrong_peer;return; }
        seq=c80_get16(p+22);if(sub==8) qos=c80_get16(p+24);
        da=p+16;sa=p+10;payload=p+header;n=bytes-header;
        if(payload[0]!=0xaa || payload[1]!=0xaa || payload[2]!=3 || payload[3] || payload[4] || payload[5]) { ++r->data_bad_llc;return; }
        type=c80_be16(payload+6);payload+=8;n-=8;
    }
    sub=(fc>>4)&15;
    if((fc&15)!=8 || (sub!=0 && sub!=8) || (fc&0xc700)!=0x100 || (seq&15) || (sub==8 && (qos&0x80)) || (v[7]&3)) { ++r->data_bad_format;return; }
    ++r->data_seen;r->data_last_rxd1=c80_get32(v+4);r->data_last_rxd2=c80_get32(v+8);r->data_last_fc=fc;r->data_last_ethertype=type;
    /* OEM metadata exports FCS/ICV errors from RXD2 bits17/20. Other
     * mt7615-family security/aggregation errors are conservatively refused;
     * accepted packets must also be open-mode WCID1 with pinned source. */
    if((v[10]&0x9f) || (v[11]&3) || (v[9]&0xf0)) { ++r->data_bad_status;return; }
    if(v[8]!=1 || !c80_mac_equal(sa,peer) || (!c80_mac_equal(da,own) && !c80_mac_broadcast(da))) { ++r->data_wrong_peer;return; }
    if(type==0x806) {
        ++r->data_arp;
        if(n<28 || c80_be16(payload)!=1 || c80_be16(payload+2)!=0x800 || payload[4]!=6 || payload[5]!=4 ||
           c80_be16(payload+6)!=1 || !c80_mac_equal(payload+8,peer)) { ++r->data_bad_protocol;return; }
        if(!c80_ip_equal(payload+14,2) || !c80_ip_equal(payload+24,1)) return;
        ++r->data_arp_target;type=0;
    } else if(type==0x800) {
        ++r->data_ipv4;
        if(n<20 || payload[0]!=0x45 || !(bytes=c80_be16(payload+2)) || bytes<20 || bytes>n ||
           (c80_be16(payload+6)&~0x4000u) || !payload[8]) { ++r->data_bad_protocol;return; }
        if(c80_sum16(payload,20)) { ++r->data_bad_checksum;return; }
        if(payload[9]==17) {
            if(bytes>=28 && c80_be16(payload+20)==68 && c80_be16(payload+22)==67 && c80_be16(payload+24)>=8 && c80_be16(payload+24)<=bytes-20) ++r->data_dhcp_candidates;
            return;
        }
        if(payload[9]!=1 || !c80_mac_equal(da,own) || !c80_ip_equal(payload+12,2) || !c80_ip_equal(payload+16,1)) return;
        ++r->data_icmp;payload+=20;n=bytes-20;
        if(n<8 || n>72 || payload[0]!=8 || payload[1]) { ++r->data_bad_protocol;return; }
        if(c80_sum16(payload,n)) { ++r->data_bad_checksum;return; }
        type=1;
    } else { ++r->data_other;return; }
    if(r->diag_captured[type]) { ++r->diag_duplicate[type];return; }
    now=io->time_us(io->context);
    if(now<r->assoc_window_start_us || now-r->assoc_window_start_us>28000000) { ++r->data_late;return; }
    c80_data_frame(io,r,type,payload,n);
}

static void c80_management_receive(struct c80_io *io,struct c80_result *r,
                                    const c80_u8 *p,c80_u32 bytes)
{
    static const c80_u8 ssid[9]={'C','8','0','-','R','A','M','1','6'};
    const c80_u8 *own=io->pool->nvm_payload+8;
    struct c80_management_counts *m; c80_u32 fc,sub,i,nonzero=0,da,bssid;
    if(!io->management_rx_test || !r->devinfo_mac_valid || !r->nvm_equal ||
       (r->phase!=38 && r->phase!=37)) return;
    m=&r->management[r->phase==37];
    if(bytes<2) { ++m->short_header; return; }
    fc=c80_get16(p);
    if(fc&3) { ++m->bad_fc; return; }
    if((fc>>2)&3) return; /* data/control have no management layout */
    if(bytes<24) { ++m->short_header; return; }
    if(fc&0x300) { ++m->bad_fc; return; } /* management ToDS/FromDS invalid */
    sub=(fc>>4)&15; ++m->headers; ++m->subtype[sub];
    for(i=0;i<6;++i) nonzero|=p[10+i];
    if((p[10]&1) || !nonzero || c80_mac_equal(p+10,own)) { ++m->peer_bad; return; }
    da=c80_mac_equal(p+4,own); bssid=c80_mac_equal(p+16,own);
    if(da) ++m->to_us;
    if(fc&0xc000) { ++m->protected_ordered; return; }
    if((fc&0x400) || (c80_get16(p+22)&15)) { ++m->fragments; return; }
    if(sub==4) {
        if(!(da || c80_mac_broadcast(p+4)) || !(bssid || c80_mac_broadcast(p+16))) return;
        ++m->probe_eligible;
        /* Only inspect the first SSID IE. Do not assume the trailing FCS
         * was stripped, and do not interpret arbitrary remaining IEs. */
        if(bytes<26 || p[24]!=0 || p[25]>32 || p[25]>bytes-26) { ++m->probe_short_ssid; return; }
        if(!p[25]) { ++m->probe_wildcard; return; }
        if(p[25]==sizeof(ssid)) {
            for(i=0;i<sizeof(ssid);++i) if(p[26+i]!=ssid[i]) break;
            if(i==sizeof(ssid)) { ++m->probe_test_ssid; return; }
        }
        ++m->probe_other_ssid; return;
    }
    if(!da || !bssid) return;
    if(sub==11) {
        if(bytes<30) { ++m->short_header; return; }
        ++m->auth_to_us;
        if(!c80_get16(p+24) && c80_get16(p+26)==1 && !c80_get16(p+28)) { ++m->auth_open_request;c80_auth_capture(io,r,p+10); }
        else ++m->auth_other;
    } else if(sub==0 || sub==2 || sub==10 || sub==12) {
        c80_u32 need=sub==0?28:sub==2?34:26;
        if(bytes<need) { ++m->short_header; return; }
        if(sub==0) { ++m->assoc_to_us;
            if(io->auth_reply_test && r->auth_submitted && c80_mac_equal(p+10,io->pool->auth_frame+4)) ++r->auth_same_peer_assoc;
            c80_assoc_capture(io,r,p,bytes);
        }
        else if(sub==2) ++m->reassoc_to_us;
        else if(sub==10) ++m->disassoc_to_us;
        else ++m->deauth_to_us;
    }
}
/* Exact OEM4031b680/type and4031b68c..b728/group/padding rules. RX0
 * frames never enter the MCU event decoder when this experiment is enabled.
 * Read only completed single-buffer descriptors. Recycle only after parsing
 * when explicitly enabled; otherwise preserve the legacy bounded trace. */
static c80_u32 c80_radio_receive(struct c80_io *io,struct c80_result *r)
{
    c80_u32 index,ctrl,size,total,type,group,offset,budget=0; const c80_u8 *p;
    while(io->rx0_rearm_test || r->rx_next[0]<C80_RX_N-1) {
        /* Do not monopolize the MCU-event/clock/stop path under continuous RX. */
        if(budget==C80_RX_N) { ++r->rx0_budget_yields; break; }
        index=r->rx_next[0];
        if(index>=C80_RX_N) { r->radio_rx_bad=4; return C80_RADIO_RX_BAD; }
        ctrl=io->pool->rx[0][index].ctrl;
        if(!(ctrl&C80_DONE)) break;
        io->dma_order(io->context,0); size=(ctrl>>16)&0x3fff;
        if(!(ctrl&C80_LS0) || size<16 || size>C80_RX_SIZE ||
           io->pool->rx[0][index].addr!=c80_dma_address(io,io->pool->data[0][index]) ||
           io->pool->rx[0][index].addr1) { r->radio_rx_bad=1; return C80_RADIO_RX_BAD; }
        p=io->pool->data[0][index]; total=c80_get16(p); type=p[3]>>5;
        if(total<16 || total>size) { r->radio_rx_bad=2; return C80_RADIO_RX_BAD; }
        ++r->rx_next[0]; ++r->rx_packets; ++r->radio_rx_packets; ++budget;
        r->radio_rx_bytes+=total; ++r->radio_rx_types[type];
        if(!r->radio_first_valid) {
            r->radio_first_valid=1; r->radio_first_dw0=c80_get32(p);
            r->radio_first_dw1=c80_get32(p+4);
        }
        if(type!=2) goto recycle;
        group=(p[3]>>1)&15;
        offset=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4);
        if(p[6]&0x40) offset+=2;
        if(offset>total) { r->radio_rx_bad=3; return C80_RADIO_RX_BAD; }
        c80_data_receive(io,r,p,total,offset);
        if(p[6]&0x80) { ++r->radio_rx_translated; goto recycle; }
        ++r->radio_raw_frames;
        c80_management_receive(io,r,p+offset,total-offset);
        c80_assoc_data_observe(io,r,p+offset,total-offset);
        /* Count only complete raw management-beacon header candidates.
         * No addresses/SSID/payload are saved or printed. FCS not verified. */
        if(total-offset>=36 && (c80_get16(p+offset)&0xfc)==0x80 &&
           !(c80_get16(p+offset)&3)) ++r->radio_beacon_headers;
recycle:
        if(io->rx0_rearm_test) {
            /* OEM402f3f6c..402f402c resets capacity,clears DONE,preserves LS0,
             * advances modulo size and records the consumed slot as CPU idx.
             * Caller402b2620..2644 publishes it at the ring's4408 register.
             * We keep no packet pointer,so reuse this coherent buffer instead
             * of allocating a replacement OS packet. No DMA enable writes. */
            io->pool->rx[0][index].addr1=0; io->pool->rx[0][index].info=0;
            io->pool->rx[0][index].ctrl=(ctrl&C80_LS0)|(C80_RX_SIZE<<16);
            ++r->rx0_rearmed;
            io->dma_order(io->context,1);
            r->rx0_last_cpu=index;
            c80_write(io,0x18004408,index); ++r->rx0_publishes;
            r->rx0_readback=c80_read(io,0x18004408);
            if(r->rx0_readback!=index) return C80_RX0_RETURN_FAILED;
            r->rx_next[0]=(index+1)%C80_RX_N;
        }
    }
    if(!io->rx0_rearm_test && r->rx_next[0]==C80_RX_N-1) r->radio_rx_full=1;
    return 0;
}
static const c80_u8 c80_radio_ext[5]={0x46,8,0x4e,0x46,0x46};
static c80_u32 c80_radio_index(c80_u32 phase) { return phase==32?4:phase-27; }
static c80_u32 c80_parse_event(struct c80_io *io,struct c80_result *r,
    const c80_u8 *p,c80_u32 size,c80_u32 sequence,c80_u32 event,c80_u32 *status)
{
    c80_u32 n;
    if(size<25) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
    r->last_event_len=c80_get16(p+16);
    r->last_packet_id=c80_get16(p+18);
    r->last_event_id=p[20]; r->last_event_seq=p[21];
    if(r->last_event_len<9 || r->last_event_len>size-16) return C80_RX_BAD;
    /* OEM4026410c treats generic EID1 status at event+8; semaphore
     * EID4 has the same8-byte event prefix. Do not accept unrelated IDs. */
    r->last_event_ext=p[20]==0xed?p[24]:0;
    r->last_event_status=p[20]==0xed?0:p[24];
    if(r->last_packet_id!=0xe000 || p[20]!=event || p[21]!=sequence) {
        ++r->rx_ignored; return C80_RX_TIMEOUT;
    }
    if(event==0xed) {
        if(r->sta_waiting) {
            c80_u32 k=r->sta_waiting-1;
            if(k>1) return C80_STA_BAD_REPLY;
            if(p[24]!=0 && p[24]!=0x25) { ++r->rx_ignored;return C80_RX_TIMEOUT; }
            r->sta_ext[k]=p[24];r->sta_event_bytes[k]=r->last_event_len;r->sta_dma_bytes[k]=size;
            if(size<44 || r->last_event_len<28) return C80_STA_BAD_REPLY;
            r->sta_echo[k]=p[28];r->sta_status[k]=c80_get32(p+32);r->sta_tail[k]=r->last_event_len-28;
            if(r->sta_echo[k]!=0x25) return C80_STA_BAD_REPLY;
            /* Actual OEM callback consumes status only. Remaining base
             * metadata is observed, not assumed to be a proven TPOS ABI. */
            r->sta_meta_valid[k]=1;r->sta_meta_bss[k]=p[36];r->sta_meta_wcid[k]=p[37];
            r->sta_meta_count[k]=c80_get16(p+38);r->sta_meta_muar[k]=p[40];
            r->sta_valid[k]=1;*status=r->sta_status[k];return 0;
        }
        if(r->phase==39 || r->phase==40) {
            c80_u32 k=r->phase-39;
            if(p[24]!=0x3c) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->tsf_ext[k]=p[24]; r->tsf_event_bytes[k]=r->last_event_len; r->tsf_dma_bytes[k]=size;
            if(r->last_event_len!=24 || size<40) return C80_TSF_BAD_REPLY;
            r->tsf_category[k]=c80_get16(p+28);
            if(r->tsf_category[k]!=2) return C80_TSF_BAD_REPLY;
            r->tsf_low[k]=c80_get32(p+32); r->tsf_high[k]=c80_get32(p+36);
            r->tsf_valid[k]=1; *status=0; return 0;
        }
        if(r->phase>=33 && r->phase<=36) {
            c80_u32 k=r->phase-33,sync=k==0 || k==3,ext=sync?0x26:0x49;
            if(p[24]!=0 && p[24]!=ext) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->beacon_ext[k]=p[24]; r->beacon_event_bytes[k]=r->last_event_len;
            r->beacon_dma_bytes[k]=size;
            /* Sync flags27 minimum16;offload flags0f expectedffff ignores
             * OEMlengthcheck. Host requires8B base and full DMA bounds. */
            if(r->last_event_len<(sync?28u:20u) || size<(sync?44u:36u))
                return C80_BEACON_BAD_REPLY;
            r->beacon_base_read[k]=1; r->beacon_tail_bytes[k]=r->last_event_len-(sync?28:20);
            r->beacon_echo[k]=p[28]; r->beacon_status[k]=c80_get32(p+32);
            if(r->beacon_echo[k]!=ext) return C80_BEACON_BAD_REPLY;
            if(sync) {
                r->beacon_index[k]=p[36]; r->beacon_count[k]=c80_get16(p+38);
                if(!r->beacon_status[k] && (r->beacon_index[k] || r->beacon_count[k]!=1))
                    return C80_BEACON_BAD_REPLY;
            }
            r->beacon_valid[k]=1; *status=r->beacon_status[k]; return 0;
        }
        if((r->phase>=27 && r->phase<=30) || r->phase==32) {
            c80_u32 step=c80_radio_index(r->phase),ext=c80_radio_ext[step];
            if(p[24]!=0 && p[24]!=ext) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->radio_ext[step]=p[24]; r->radio_event_bytes[step]=r->last_event_len;
            r->radio_dma_bytes[step]=size;
            /* Actual flags0f: fixed8B body,12B extended event prefix. */
            if(size<36 || r->last_event_len!=20) return C80_RADIO_BAD_REPLY;
            r->radio_echo[step]=p[28]; r->radio_status[step]=c80_get32(p+32);
            if(r->radio_echo[step]!=ext) return C80_RADIO_BAD_REPLY;
            r->radio_valid[step]=1; *status=r->radio_status[step]; return 0;
        }
        if(r->phase==25 || r->phase==26) {
            c80_u32 step=r->phase-25;
            /* Actual BSS builder402ee440: ext26, flags0x27/minimum16B,
             * callback402eccdc status at body+4. Same bounded variable
             * envelope as DEVINFO; add strict echo/index/TLV-count. */
            if(p[24]!=0 && p[24]!=0x26) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->bss_ext[step]=p[24]; r->bss_event_bytes[step]=r->last_event_len;
            r->bss_dma_bytes[step]=size;
            if(size<44 || r->last_event_len<28) return C80_BSS_BAD_REPLY;
            r->bss_base_read[step]=1; r->bss_tail_bytes[step]=r->last_event_len-28;
            r->bss_echo[step]=p[28]; r->bss_status[step]=c80_get32(p+32);
            r->bss_index[step]=p[36]; r->bss_count[step]=c80_get16(p+38);
            if(r->bss_echo[step]!=0x26) return C80_BSS_BAD_REPLY;
            if(!r->bss_status[step] &&
               (r->bss_index[step] || r->bss_count[step]!=(step?1u:2u)))
                return C80_BSS_BAD_REPLY;
            r->bss_valid[step]=1; *status=r->bss_status[step]; return 0;
        }
        if(r->phase==23 || r->phase==24) {
            c80_u32 step=r->phase-23;
            /* OEM flags0x27 include variable-response bit0x20. Actual
             * dispatcher402637b4/4026419c accepts >=16B body and passes
             * its real length to callback402ecc4c. RAM12 measured40B
             * event=12B header+28B body. Read only the16B base; its tail
             * has no fields consumed by the OEM callback. The preceding
             * envelope checks bound the entire declared event to DMA. */
            if(p[24]!=0 && p[24]!=0x2a) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->devinfo_ext[step]=p[24];
            r->devinfo_event_bytes[step]=r->last_event_len;
            r->devinfo_dma_bytes[step]=size;
            if(size<44 || r->last_event_len<28)
                return C80_DEVINFO_BAD_REPLY;
            r->devinfo_tail_bytes[step]=r->last_event_len-28;
            r->devinfo_base_read[step]=1; r->devinfo_echo[step]=p[28];
            r->devinfo_status[step]=c80_get32(p+32);
            r->devinfo_ownmac[step]=p[36]; r->devinfo_count[step]=c80_get16(p+38);
            if(r->devinfo_echo[step]!=0x2a) return C80_DEVINFO_BAD_REPLY;
            if(!r->devinfo_status[step] &&
               (r->devinfo_ownmac[step] || r->devinfo_count[step]!=1))
                return C80_DEVINFO_BAD_REPLY;
            r->devinfo_valid[step]=1; *status=r->devinfo_status[step]; return 0;
        }
        if(r->phase==21) {
            /* Generic extended-command result:12B header +8B body.
             * OEM SET's callback is a NOP; additionally check echo21
             * and the full32-bit firmware status here. */
            if(p[24]!=0) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            if(size<36 || r->last_event_len!=20 || p[28]!=0x21)
                return C80_NVM_BAD_REPLY;
            r->nvm_set_status=c80_get32(p+32); r->nvm_set_valid=1;
            *status=r->nvm_set_status; return 0;
        }
        if(r->phase==22) {
            /* OEM4030eb8c:source/format/offset/count6B then content.
             * Matched-sequence OEM dispatch accepts both command echo
             *9b and documented buffer-read result8a. Bound everything
             * independently, then compare every requested byte. OEM's
             * callback copies count bytes at body+6 and ignores trailing
             * alignment. RAM10 measured1044=ALIGN4(12+6+1024). */
            if(p[24]!=0x8a && p[24]!=0x9b) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
            r->nvm_get_ext=p[24];
            if(size<34 || r->last_event_len<18) return C80_NVM_BAD_REPLY;
            r->nvm_get_source=p[28]; r->nvm_get_format=p[29];
            r->nvm_get_offset=c80_get16(p+30); r->nvm_get_count=c80_get16(p+32);
            /* Earlier generic event bounds require the complete declared
             * event to fit the DMA frame, including any two pad bytes.
             * Accept exactly the packed length or its4-byte alignment;
             * no arbitrary extra bytes, shortened content or new offset. */
            if(r->last_event_len!=18+C80_NVM_BYTES &&
               r->last_event_len!=((18+C80_NVM_BYTES+3)&~3u))
                return C80_NVM_BAD_REPLY;
            if(r->nvm_get_source!=1 || r->nvm_get_format!=1 ||
               r->nvm_get_offset || r->nvm_get_count!=C80_NVM_BYTES)
                return C80_NVM_BAD_REPLY;
            r->nvm_get_padding=r->last_event_len-(18+C80_NVM_BYTES);
            r->nvm_get_valid=1; r->nvm_get_crc=c80_crc(p+34,C80_NVM_BYTES);
            for(n=0;n<C80_NVM_BYTES;++n) {
                r->nvm_compared=n+1;
                if(p[34+n]!=io->pool->nvm_payload[4+n]) {
                    r->nvm_mismatch_valid=1; r->nvm_mismatch_offset=n;
                    return C80_NVM_MISMATCH;
                }
            }
            r->nvm_equal=1; *status=0; return 0;
        }
        /* Actual OEM EIDed dispatch uses a12B event header, then
         * category5/count@4/counters@8. Only the one requested counter
         * is accepted, with exact event length and strict DMA bounds. */
        if(p[24]!=0x3c) { ++r->rx_ignored; return C80_RX_TIMEOUT; }
        if(size<40 || r->last_event_len!=24) return C80_QUERY_BAD;
        r->counter_category=c80_get16(p+28); r->counter_count=p[32];
        if(r->counter_category!=5 || r->counter_count!=1) return C80_QUERY_BAD;
        r->counter_value=c80_get32(p+36); r->counter_query_valid=1;
        *status=0; return 0;
    }
    *status=p[24]; return 0;
}
static void c80_unmatched_event(struct c80_result *r,const c80_u8 *p,c80_u32 size)
{
    ++r->rx1_unmatched; r->rx1_short+=size<25;
    r->rx1_meta_valid=0; r->rx1_meta_phase=r->phase; r->rx1_meta_dma_bytes=size;
    r->rx1_meta_event_bytes=r->rx1_meta_pid=r->rx1_meta_eid=r->rx1_meta_seq=r->rx1_meta_ext=0;
    if(size>=18) { r->rx1_meta_event_bytes=c80_get16(p+16);r->rx1_meta_valid|=1; }
    if(size>=20) { r->rx1_meta_pid=c80_get16(p+18);r->rx1_meta_valid|=2; }
    if(size>=21) { r->rx1_meta_eid=p[20];r->rx1_meta_valid|=4; }
    if(size>=22) { r->rx1_meta_seq=p[21];r->rx1_meta_valid|=8; }
    if(size>=25 && p[20]==0xed) { r->rx1_meta_ext=p[24];r->rx1_meta_valid|=16; }
}
static c80_u32 c80_return_event(struct c80_io *io,struct c80_result *r,c80_u32 index,c80_u32 control)
{
    /* Actual OEM RX1 callback/publication uses the same LS0-preserving
     * capacity reset as RX0, then CPU consumed-slot index at4418. */
    io->pool->rx[1][index].addr1=0;io->pool->rx[1][index].info=0;
    io->pool->rx[1][index].ctrl=(control&C80_LS0)|(C80_RX_SIZE<<16);
    ++r->rx1_rearmed;io->dma_order(io->context,1);
    r->rx1_last_cpu=index;c80_write(io,0x18004418,index);++r->rx1_publishes;
    r->rx1_readback=c80_read(io,0x18004418);
    if(r->rx1_readback!=index) return C80_RX1_RETURN_FAILED;
    r->rx_next[1]=(index+1)%C80_RX_N;return 0;
}
/* Actual OEM402b327c dispatches packet type6 to402b2f2c, independently
 * of MCU events (type7). TX-free header8B, count7bits, report type6bits,
 * version0 uses2B token entries; nonzero versions use4B with low16 token.
 * The OEM checks embedded length=8+count*stride. Additionally bound it to
 * the descriptor, permitting only alignment padding. No packet/address
 * is retained and no completion here releases the pinned payload pool. */
static c80_u32 c80_rx1_non_event(struct c80_result *r,const c80_u8 *p,c80_u32 size,c80_u32 type)
{
    c80_u32 dw0,dw1,count,stride,bytes,i,ours=0,peer=0,foreign=0,diag[2]={0,0};
    ++r->rx1_non_event;r->rx1_last_type=type;r->rx1_last_bytes=size;
    r->rx1_last_dw0=c80_get32(p);
    if(type!=6) { ++r->rx1_unknown;return C80_RX_TIMEOUT; }
    ++r->txfree_reports;
    r->txfree_dw0=dw0=c80_get32(p);r->txfree_bytes=size;
    r->txfree_dw1=r->txfree_report_type=r->txfree_count=r->txfree_version=0;
    if(size<8) goto bad;
    r->txfree_dw1=dw1=c80_get32(p+4);
    r->txfree_report_type=(dw0>>23)&63;
    r->txfree_count=count=(dw0>>16)&127;
    r->txfree_version=(dw1>>16)&7;
    bytes=dw0&0xffff;
    /* Unknown report subtypes cannot complete a token; recycle bounded
     * DMA without pretending they are MCU replies or reading their body. */
    if(r->txfree_report_type) { ++r->txfree_other;return C80_RX_TIMEOUT; }
    stride=r->txfree_version?4:2;
    if(bytes!=8+count*stride || bytes>size || size!=((bytes+3)&~3u)) goto bad;
    /* Validate the complete list before committing any completion count. */
    for(i=0;i<count;++i) {
        c80_u32 token=c80_get16(p+8+i*stride);
        if(token>4095) goto bad;
        if(!token) ++ours;else if(token==1) ++peer;else if(token==2 || token==3) ++diag[token-2];else ++foreign;
    }
    foreign+=(r->diag_submitted[0]?0:diag[0])+(r->diag_submitted[1]?0:diag[1]);
    ++r->txfree_valid;r->txfree_tokens+=count;r->txfree_foreign+=foreign+(r->assoc_submitted?0:peer);
    if(!r->auth_submitted) r->txfree_before_submit+=ours;
    else if(ours) {
        r->txfree_duplicate+=ours-(r->auth_token_returned?0:1);
        r->txfree_ours+=ours;r->auth_token_returned=1;
    }
    if(!r->assoc_submitted) r->assoc_free_before+=peer;
    else if(peer) {
        r->assoc_free_duplicate+=peer-(r->assoc_token_returned?0:1);
        r->txfree_duplicate+=peer-(r->assoc_token_returned?0:1);
        r->txfree_ours+=peer;r->assoc_token_returned=1;
    }
    for(i=0;i<2;++i) {
        if(!r->diag_submitted[i]) r->diag_early[i]+=diag[i];
        else if(diag[i]) {
            r->diag_dup_free[i]+=diag[i]-(r->diag_token_returned[i]?0:1);
            r->txfree_duplicate+=diag[i]-(r->diag_token_returned[i]?0:1);
            r->txfree_ours+=diag[i];r->diag_token_returned[i]=1;
        }
    }
    return C80_RX_TIMEOUT;
bad:
    ++r->txfree_bad;return C80_RX1_NOTIFY_BAD;
}
static c80_u32 c80_receive(struct c80_io *io,struct c80_result *r,
                           c80_u32 sequence,c80_u32 event,c80_u32 *status)
{
    c80_u32 q,index,control,size,n,rc,returned,recycle,non_event,type;const c80_u8 *p;
    if(io->radio_test) { rc=c80_radio_receive(io,r);if(rc) return rc; }
    for(q=io->radio_test?1:0;q<2;++q) {
        recycle=q==1 && io->rx1_rearm_test;
        for(n=0;n<C80_RX_N;++n) {
            index=r->rx_next[q];
            if(index>=(recycle?C80_RX_N:C80_RX_N-1)) return C80_RX_BAD;
            control=io->pool->rx[q][index].ctrl;
            if(!(control&C80_DONE)) break;
            io->dma_order(io->context,0);size=(control>>16)&0x3fff;
            ++r->rx_packets;if(!recycle) ++r->rx_next[q];
            if(!(control&C80_LS0) || !size || size>C80_RX_SIZE ||
               (recycle && (size<(io->rx1_packet_test?4u:16u) || io->pool->rx[q][index].addr!=c80_dma_address(io,io->pool->data[q][index]) || io->pool->rx[q][index].addr1))) {
                r->rx_bad_ctrl=control;return C80_RX_BAD;
            }
            p=io->pool->data[q][index];if(recycle) ++r->rx1_packets;
            non_event=0;
            if(recycle && io->rx1_packet_test) {
                type=c80_get32(p)>>29;++r->rx1_type[type];
                if(type!=7) non_event=1;
                else if(size<16) { r->rx_bad_ctrl=control;return C80_RX_BAD; }
            }
            rc=non_event?c80_rx1_non_event(r,p,size,type):c80_parse_event(io,r,p,size,sequence,event,status);
            if(recycle && (rc==0 || rc==C80_RX_TIMEOUT)) {
                if(rc==C80_RX_TIMEOUT && !non_event) c80_unmatched_event(r,p,size);
                returned=c80_return_event(io,r,index,control);if(returned) return returned;
            }
            if(rc!=C80_RX_TIMEOUT) return rc;
        }
        if(recycle && n==C80_RX_N) ++r->rx1_budget_yields;
    }
    return C80_RX_TIMEOUT;
}
static c80_u32 c80_next_sequence(struct c80_result *r)
{
    r->sequence=r->sequence==15?1:r->sequence+1;
    return r->sequence;
}
static int c80_download_mode(struct c80_io *io,struct c80_result *r)
{
    r->download_last_glo=c80_read(io,C80_GLO);
    return r->download_last_glo!=0xffffffffu &&
           (r->download_last_glo&C80_DOWNLOAD_MODE);
}
/* Preserve the live transport state BEFORE cleanup changes the ring controls.
 * Only already-used readable registers and coherent descriptors are read.
 * No acknowledgement, reset, interrupt enable or diagnostic selector writes. */
static void c80_transport_snapshot(struct c80_io *io,struct c80_result *r,
                                    c80_u32 ring,c80_u32 slot,struct c80_desc *d)
{
    r->failure_snapshot=1; r->failure_phase=r->phase;
    r->failure_ring=ring; r->failure_slot=slot;
    io->dma_order(io->context,0);
    r->failure_desc[0]=d->addr; r->failure_desc[1]=d->ctrl;
    r->failure_desc[2]=d->addr1; r->failure_desc[3]=d->info;
    r->failure_cpu=c80_read(io,0x18004308+16*ring);
    r->failure_dma=c80_read(io,0x1800430c+16*ring);
    r->failure_glo=c80_read(io,C80_GLO);
    r->failure_mask=c80_read(io,C80_MASK);
    r->failure_source=c80_read(io,C80_SOURCE);
    r->failure_sync=c80_read(io,C80_SYNC);
    r->failure_own=c80_read(io,C80_OWN);
}
static void c80_record_nvm_wait(struct c80_result *r,c80_u64 start,
                                c80_u64 now,c80_u32 polls)
{
    c80_u32 elapsed=now<start?0:now-start>0xffffffffu?0xffffffffu:(c80_u32)(now-start);
    if(r->sta_waiting && r->sta_waiting<=2) {
        r->sta_wait_us[r->sta_waiting-1]=elapsed;r->sta_polls[r->sta_waiting-1]=polls;
    } else if(r->phase==21) {
        r->nvm_set_wait_us=elapsed; r->nvm_set_polls=polls;
        if(now<start) r->nvm_wait_clock_backwards|=1;
    } else if(r->phase==22) {
        r->nvm_get_wait_us=elapsed; r->nvm_get_polls=polls;
        if(now<start) r->nvm_wait_clock_backwards|=2;
    } else if(r->phase==23 || r->phase==24) {
        r->devinfo_wait_us[r->phase-23]=elapsed;
        r->devinfo_polls[r->phase-23]=polls;
    } else if(r->phase==25 || r->phase==26) {
        r->bss_wait_us[r->phase-25]=elapsed;
        r->bss_polls[r->phase-25]=polls;
    } else if((r->phase>=27 && r->phase<=30) || r->phase==32) {
        c80_u32 step=c80_radio_index(r->phase);
        r->radio_wait_us[step]=elapsed; r->radio_polls[step]=polls;
    } else if(r->phase>=33 && r->phase<=36) {
        r->beacon_wait_us[r->phase-33]=elapsed; r->beacon_polls[r->phase-33]=polls;
    } else if(r->phase==39 || r->phase==40) {
        r->tsf_wait_us[r->phase-39]=elapsed; r->tsf_polls[r->phase-39]=polls;
    }
}
static c80_u32 c80_exchange(struct c80_io *io,struct c80_result *r,c80_u32 cid,
                            const c80_u8 *body,c80_u32 bytes,c80_u32 *reply)
{
    c80_u32 slot=r->command_submitted,sequence=c80_next_sequence(r),i,rx=0,tx=0,rc,len;
    c80_u32 nvm=cid==0xed && (r->phase==21 || r->phase==22);
    c80_u32 devinfo=cid==0xed && r->phase>=23 && r->phase<=26;
    c80_u32 radio=cid==0xed && ((r->phase>=27 && r->phase<=30) || r->phase==32);
    c80_u32 beacon=cid==0xed && r->phase>=33 && r->phase<=36;
    c80_u32 tsf=cid==0xed && (r->phase==39 || r->phase==40);
    c80_u32 sta=cid==0xed && r->sta_waiting && r->sta_waiting<=2 && io->assoc_reply_test && r->phase==37;
    c80_u32 timeout=sta?1000000u:nvm?C80_NVM_WAIT_US:(beacon || tsf)?6000000u:radio?(r->phase==28?5000000u:6000000u):devinfo?C80_DEVINFO_WAIT_US:2000000u;
    c80_u32 poll_us=(nvm || devinfo || radio || beacon || tsf || sta)?C80_NVM_POLL_US:50u;
    c80_u32 max_polls=(nvm || devinfo || radio || beacon || tsf || sta)?timeout/poll_us:C80_MAX_POLLS;
    c80_u64 start,now; struct c80_desc *d;
    if(slot>=C80_COMMAND_SLOTS || bytes>C80_COMMAND_BYTES-64 || !sequence || sequence>15) return C80_TX_TIMEOUT;
    if(cid==0xed) {
        if(!r->main_ready || r->phase<20 || (r->phase>36 && !tsf && !sta)) return C80_QUERY_BAD;
        if(c80_read(io,C80_GLO)==0xffffffffu || (c80_read(io,C80_GLO)&C80_DOWNLOAD_MODE))
            return C80_MODE_REFUSED;
    } else if(!c80_download_mode(io,r)) return C80_MODE_REFUSED;
    len=c80_command(io->pool->command[slot],cid,body,bytes,sequence);
    if(cid==0xed && r->phase==21) {
        io->pool->command[slot][38]=1; io->pool->command[slot][41]=0x21;
    }
    if(sta) io->pool->command[slot][41]=0x25;
    if(cid==0xed && r->phase==22) io->pool->command[slot][41]=0x9b;
    /* OEM flags0x27 encode query0 here, despite the mutating command name.
     * Preserve the ARM-produced header; don't infer SetQuery from its name. */
    if(cid==0xed && (r->phase==23 || r->phase==24)) io->pool->command[slot][41]=0x2a;
    if(cid==0xed && (r->phase==25 || r->phase==26)) io->pool->command[slot][41]=0x26;
    if(radio) {
        io->pool->command[slot][38]=1;
        io->pool->command[slot][41]=c80_radio_ext[c80_radio_index(r->phase)];
    }
    if(beacon) {
        c80_u32 k=r->phase-33,sync=k==0 || k==3;
        io->pool->command[slot][38]=sync?0:1;
        io->pool->command[slot][41]=sync?0x26:0x49;
    }
    d=&io->pool->tx[slot]; d->addr=c80_dma_address(io,io->pool->command[slot]);
    d->addr1=0; d->info=0; d->ctrl=C80_LS0|(len<<16);
    io->dma_order(io->context,1);
    ++r->command_submitted; ++r->tx_submitted;
    c80_write(io,0x180043f8,r->command_submitted);
    start=io->time_us(io->context);
    for(i=0;i<max_polls;++i) {
        /* NVM follows OEM60s, DEVINFO the OEM6s default. A second iteration
         * cap also bounds a frozen clock; rollback fails without unsigned
         * wrap. No command is retried or resent while waiting. */
        if(nvm || devinfo || radio || beacon || tsf || sta) {
            now=io->time_us(io->context);
            if(now<start || now-start>=timeout) break;
        }
        if(!tx && (d->ctrl&C80_DONE) && c80_read(io,0x180043fc)==r->command_submitted) {
            io->dma_order(io->context,0); tx=1; ++r->command_completed; ++r->tx_completed;
        }
        if(!rx) {
            rc=c80_receive(io,r,sequence,cid==0x10?4:cid==0xed?0xed:1,reply);
            if(rc && rc!=C80_RX_TIMEOUT) {
                c80_record_nvm_wait(r,start,io->time_us(io->context),i+1);
                return rc;
            }
            if(!rc) rx=1;
        }
        if(rx && tx) {
            c80_record_nvm_wait(r,start,io->time_us(io->context),i+1);
            return 0;
        }
        now=io->time_us(io->context);
        if(now<start || now-start>=timeout) break;
        io->delay_us(io->context,poll_us);
    }
    c80_record_nvm_wait(r,start,io->time_us(io->context),i<max_polls?i:max_polls);
    c80_transport_snapshot(io,r,15,slot,d);
    return tx?C80_RX_TIMEOUT:C80_TX_TIMEOUT;
}
/* Actual OEM BASIC/WTBL profile from trace-stock-station.py. Synthetic
 * template MACs are zeroed; fill only from the validated captured peer. */
static c80_u32 c80_sta_exchange(struct c80_io *io,struct c80_result *r,c80_u32 off)
{
    static const c80_u8 on[244]={0x00,0x01,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x01,0x00,0x01,0x00,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x0d,0x00,0xd8,0x00,0x01,0x01,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x0c,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x09,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x08,0x00,0x00,0x01,0x00,0x00,0x0c,0x00,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const c80_u8 del[28]={0x00,0x01,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00};
    c80_u8 body[244];c80_u32 i,n=off?28:244,rc,status=~0u;
    if(!io->assoc_reply_test || r->phase!=37 || !r->assoc_captured || !r->auth_token_returned ||
       !r->auth_dma_done || !r->auth_submitted || (off && (!r->sta_valid[0] || r->sta_status[0]))) return C80_ASSOC_BAD_PREREQ;
    for(i=0;i<n;++i) body[i]=off?del[i]:on[i];
    for(i=0;i<6;++i) { body[20+i]=io->pool->auth_frame[4+i];if(!off) body[44+i]=body[20+i]; }
    r->sta_waiting=off+1;r->sta_attempted[off]=1;
    rc=c80_exchange(io,r,0xed,body,n,&status);r->sta_waiting=0;
    if(rc) return rc;
    if(!r->sta_valid[off] || status) return C80_STA_REJECTED;
    return 0;
}
static c80_u32 c80_assoc_step(struct c80_io *io,struct c80_result *r)
{
    c80_u64 now;struct c80_desc *d=&io->pool->auth_tx[1];c80_u32 rc;
    if(!io->assoc_reply_test || !r->assoc_captured || r->assoc_dma_done) return 0;
    if(r->phase!=37 || !r->auth_ring_programmed || !r->auth_submitted || !r->auth_dma_done) return C80_ASSOC_BAD_PREREQ;
    now=io->time_us(io->context);
    if(now<r->assoc_window_start_us) return C80_BAD_TIMER;
    if(now-r->assoc_window_start_us>29000000) return C80_ASSOC_TIMEOUT;
    if(!r->auth_token_returned) return 0;
    if(!r->sta_attempted[0]) { rc=c80_sta_exchange(io,r,0);if(rc) return rc; }
    if(!r->sta_valid[0] || r->sta_status[0]) return C80_ASSOC_BAD_PREREQ;
    now=io->time_us(io->context);
    if(!r->assoc_submitted) {
        if(now<r->assoc_window_start_us) return C80_BAD_TIMER;
        if(now-r->assoc_window_start_us>29000000) return C80_ASSOC_TIMEOUT;
        r->assoc_pre_base=c80_read(io,C80_AUTH_RING);r->assoc_pre_count=c80_read(io,C80_AUTH_RING+4);
        if(r->assoc_pre_base!=c80_dma_address(io,io->pool->auth_tx) || r->assoc_pre_count!=C80_AUTH_N ||
           c80_read(io,C80_AUTH_RING+8)!=1 || c80_read(io,C80_AUTH_RING+12)!=1 ||
           d->ctrl!=C80_DONE || d->addr || d->addr1 || d->info) return C80_ASSOC_BAD_DESC;
        d->addr=c80_dma_address(io,io->pool->assoc_header);d->addr1=c80_dma_address(io,io->pool->assoc_frame);d->info=0;
        d->ctrl=C80_LS0|(64u<<16);io->dma_order(io->context,1);
        r->assoc_submitted=1;r->assoc_submit_us=now;
        c80_write(io,C80_AUTH_RING+8,2);r->assoc_cpu_readback=c80_read(io,C80_AUTH_RING+8);
        if(r->assoc_cpu_readback!=2) return C80_ASSOC_PUBLISH;
    }
    if(now<r->assoc_submit_us) return C80_BAD_TIMER;
    r->assoc_wait_us=now-r->assoc_submit_us>0xffffffffu?0xffffffffu:(c80_u32)(now-r->assoc_submit_us);++r->assoc_polls;
    r->assoc_ctrl=d->ctrl;r->assoc_dma_index=c80_read(io,C80_AUTH_RING+12);
    if(r->assoc_dma_index<1 || r->assoc_dma_index>2 || (r->assoc_ctrl&~C80_DONE)!=(C80_LS0|(64u<<16)) ||
       d->addr!=c80_dma_address(io,io->pool->assoc_header) || d->addr1!=c80_dma_address(io,io->pool->assoc_frame) || d->info) return C80_ASSOC_BAD_DESC;
    if((r->assoc_ctrl&C80_DONE) && r->assoc_dma_index==2) { io->dma_order(io->context,0);r->assoc_dma_done=1;return 0; }
    if(r->assoc_wait_us>=1000000) return C80_ASSOC_TIMEOUT;
    return 0;
}

/* Own and publish two previously unused ring cells, at most once per reply.
 * Header DDONE/TX-free never free, clear or reuse a response buffer/token. */
static c80_u32 c80_data_step(struct c80_io *io,struct c80_result *r)
{
    c80_u32 k,slot,expected; c80_u64 now;struct c80_desc *d;
    if(!io->data_echo_test) return 0;
    for(k=0;k<2;++k) {
        if(!r->diag_captured[k] || (r->diag_token_returned[k] && r->diag_dma_done[k])) continue;
        if(r->phase!=37 || !r->auth_ring_programmed || !r->sta_valid[0] || r->sta_status[0] ||
           !r->assoc_submitted || !r->assoc_dma_done || r->sta_attempted[1]) return C80_DATA_BAD_PREREQ;
        now=io->time_us(io->context);
        if(now<r->assoc_window_start_us) return C80_BAD_TIMER;
        if(!r->diag_submitted[k]) {
            if(now-r->assoc_window_start_us>29000000) return C80_DATA_TIMEOUT;
            if(!r->assoc_token_returned) return 0;
            if(r->diag_submitted[1-k] && !r->diag_token_returned[1-k]) return 0;
            slot=2+r->diag_submissions;if(slot>3) return C80_DATA_BAD_DESC;
            d=&io->pool->auth_tx[slot];
            if(c80_read(io,C80_AUTH_RING)!=c80_dma_address(io,io->pool->auth_tx) ||
               c80_read(io,C80_AUTH_RING+4)!=C80_AUTH_N || c80_read(io,C80_AUTH_RING+8)!=slot ||
               c80_read(io,C80_AUTH_RING+12)!=slot || d->ctrl!=C80_DONE || d->addr || d->addr1 || d->info) return C80_DATA_BAD_DESC;
            d->addr=c80_dma_address(io,io->pool->diag_header[k]);d->addr1=c80_dma_address(io,io->pool->diag_frame[k]);d->info=0;d->ctrl=C80_LS0|(64u<<16);
            io->dma_order(io->context,1);r->diag_submitted[k]=1;r->diag_slot[k]=slot;++r->diag_submissions;r->diag_submit_us[k]=now;
            c80_write(io,C80_AUTH_RING+8,slot+1);r->diag_cpu[k]=c80_read(io,C80_AUTH_RING+8);
            if(r->diag_cpu[k]!=slot+1) return C80_DATA_PUBLISH;
        }
        if(now<r->diag_submit_us[k]) return C80_BAD_TIMER;
        r->diag_wait_us[k]=now-r->diag_submit_us[k]>0xffffffffu?0xffffffffu:(c80_u32)(now-r->diag_submit_us[k]);++r->diag_polls[k];
        slot=r->diag_slot[k];expected=slot+1;d=&io->pool->auth_tx[slot];r->diag_ctrl[k]=d->ctrl;r->diag_dma[k]=c80_read(io,C80_AUTH_RING+12);
        if(r->diag_dma[k]<slot || r->diag_dma[k]>expected || (d->ctrl&~C80_DONE)!=(C80_LS0|(64u<<16)) ||
           d->addr!=c80_dma_address(io,io->pool->diag_header[k]) || d->addr1!=c80_dma_address(io,io->pool->diag_frame[k]) || d->info) return C80_DATA_BAD_DESC;
        if((d->ctrl&C80_DONE) && r->diag_dma[k]==expected) { io->dma_order(io->context,0);r->diag_dma_done[k]=1; }
        if(r->diag_wait_us[k]>=1000000 && (!r->diag_dma_done[k] || !r->diag_token_returned[k])) return C80_DATA_TIMEOUT;
    }
    return 0;
}

static c80_u32 c80_semaphore(struct c80_io *io,struct c80_result *r,
                             c80_u32 operation,c80_u32 *reply)
{
    c80_u8 body[4]; c80_put32(body,operation);
    return c80_exchange(io,r,0x10,body,4,reply);
}
static c80_u32 c80_scatter(struct c80_io *io,struct c80_result *r,
                           const c80_u8 *body,c80_u32 bytes)
{
    c80_u32 slot=r->fwdl_submitted,sequence=c80_next_sequence(r),i,len;
    c80_u64 start,now; struct c80_desc *d;
    if(slot>=C80_FRAGMENT_SLOTS || !bytes || bytes>960 || sequence>15) return C80_FWDL_TIMEOUT;
    if(!c80_download_mode(io,r)) return C80_MODE_REFUSED;
    len=c80_command(io->pool->fragment[slot],0xee,body,bytes,sequence);
    d=&io->pool->fwdl[slot]; d->addr=c80_dma_address(io,io->pool->fragment[slot]);
    d->addr1=0; d->info=0; d->ctrl=C80_LS0|(len<<16);
    io->dma_order(io->context,1); ++r->fwdl_submitted; ++r->tx_submitted;
    c80_write(io,0x18004338,r->fwdl_submitted);
    start=io->time_us(io->context);
    for(i=0;i<C80_MAX_POLLS;++i) {
        if((d->ctrl&C80_DONE) && c80_read(io,0x1800433c)==r->fwdl_submitted) {
            io->dma_order(io->context,0); ++r->fwdl_completed; ++r->tx_completed;
            if(r->phase>=14 && r->phase<=16) {
                ++r->main_chunks; r->main_bytes+=bytes;
                ++r->main_region_chunks[r->main_region_index];
                r->main_region_bytes[r->main_region_index]+=bytes;
            } else { ++r->patch_chunks; r->patch_bytes+=bytes; }
            return 0;
        }
        now=io->time_us(io->context);
        if(now<start || now-start>=2000000) break;
        io->delay_us(io->context,50);
    }
    c80_transport_snapshot(io,r,3,slot,d);
    return C80_FWDL_TIMEOUT;
}
static c80_u32 c80_patch(struct c80_io *io,struct c80_result *r,
                         const struct c80_blob *fw)
{
    c80_u32 rc,status=0,release_rc=0; c80_u8 body[12];
    c80_stage(io,r,7);
    rc=c80_semaphore(io,r,1,&r->get_status);
    if(rc) return rc;
    r->get_valid=1;
    if(r->get_status==1) {
        r->patch_ready_valid=1; r->patch_ready_status=1; return 0;
    }
    if(r->get_status!=2) return C80_SEMAPHORE;
    r->sem_held=1;
    c80_stage(io,r,8);
    c80_put32(body,0x1c000); c80_put32(body+4,1808); c80_put32(body+8,0x80000000);
    rc=c80_exchange(io,r,5,body,12,&r->patch_address_status);
    if(rc) goto release;
    r->patch_address_valid=1;
    if(r->patch_address_status) { rc=C80_DOWNLOAD_STATUS; goto release; }
    c80_stage(io,r,9);
    rc=c80_scatter(io,r,fw->data+30,960);
    if(rc) goto release;
    rc=c80_scatter(io,r,fw->data+990,848);
    if(rc) goto release;
    c80_stage(io,r,10);
    c80_put32(body,0);
    rc=c80_exchange(io,r,7,body,4,&r->patch_finish_status);
    if(rc) goto release;
    r->patch_finish_valid=1;
    if(r->patch_finish_status) { rc=C80_DOWNLOAD_STATUS; goto release; }
    r->patch_uploaded=1;
release:
    /* On explicit MCU rejection the command path is still usable. Release
     * the semaphore before stopping. After transport failure, hold MCU/reset
     * and stop DMA rather than transmitting into an unconfirmed queue. */
    if(!rc || rc==C80_DOWNLOAD_STATUS) {
        c80_stage(io,r,11); r->release_attempted=1;
        release_rc=c80_semaphore(io,r,0,&r->release_status);
        if(!release_rc) {
            r->release_valid=1;
            if(r->release_status==3) r->sem_held=0;
            else release_rc=C80_SEMAPHORE;
        }
        if(!rc) rc=release_rc;
    }
    if(rc) return rc;
    c80_stage(io,r,12);
    rc=c80_semaphore(io,r,1,&r->patch_ready_status);
    if(rc) return rc;
    r->patch_ready_valid=1;
    if(r->patch_ready_status==2) {
        r->sem_held=1; r->release_attempted=1;
        release_rc=c80_semaphore(io,r,0,&status);
        if(!release_rc && status==3) r->sem_held=0;
    }
    return r->patch_ready_status==1?0:C80_PATCH_NOT_READY;
}
/* Region metadata and byte ranges match the actual OEM402ef9e0 parser.
 * The exact six firmware lengths/CRCs are verified before peripheral writes.
 * Destinations below are MCU address-space values carried only in packets. */
static c80_u32 c80_main_firmware(struct c80_io *io,struct c80_result *r,
                                 const struct c80_blob *fw)
{
    static const c80_u32 destinations[3]={0x20400,0x2010000,0x40100000};
    static const c80_u32 lengths[3]={2896,1584,21136};
    c80_u32 i,offset=0,left,n,rc; c80_u8 body[12];
    r->main_attempted=1; c80_stage(io,r,13);
    /* OEM final sync hook requires state3, initial transfer state1.
     * Refuse an inherited running image rather than issuing a restart command.
     * State0 may settle to1; no undocumented Wi-Fi power-on writes. */
    r->main_sync_before=c80_read(io,C80_SYNC);
    if(r->main_sync_before==0xffffffffu || ((r->main_sync_before>>1)&7)>1)
        return C80_BAD_SYNC;
    if(!c80_poll(io,C80_SYNC,14,2,2000000,&r->main_sync_before)) return C80_BAD_SYNC;
    for(i=0;i<3;++i) {
        r->main_region_index=i; c80_stage(io,r,14+i);
        c80_put32(body,destinations[i]); c80_put32(body+4,lengths[i]);
        c80_put32(body+8,0x80000000);
        rc=c80_exchange(io,r,1,body,12,&r->main_region_status[i]);
        if(rc) return rc;
        r->main_region_valid|=1u<<i;
        if(r->main_region_status[i]) return C80_DOWNLOAD_STATUS;
        left=lengths[i];
        while(left) {
            n=left>960?960:left;
            if(offset>fw->bytes || n>fw->bytes-offset) return C80_BAD_FW;
            rc=c80_scatter(io,r,fw->data+offset,n);
            if(rc) return rc;
            offset+=n; left-=n;
        }
        ++r->main_regions_complete;
    }
    /* The36B separator and156B trailers are metadata, never scatter payload.
     * All feature bytes are0 in this exact image: start with flags0/address0. */
    if(offset!=25616) return C80_BAD_FW;
    c80_stage(io,r,17); c80_put32(body,0); c80_put32(body+4,0);
    r->main_start_attempted=1;
    rc=c80_exchange(io,r,2,body,8,&r->main_start_status);
    if(rc) return rc;
    r->main_start_valid=1;
    if(r->main_start_status) return C80_DOWNLOAD_STATUS;
    c80_stage(io,r,18);
    if(!c80_poll(io,C80_SYNC,14,6,2000000,&r->main_sync_after)) return C80_MAIN_NOT_READY;
    r->main_ready=1; return 0;
}
static c80_u32 c80_runtime_query(struct c80_io *io,struct c80_result *r)
{
    c80_u8 body[104]; c80_u32 i,rc,irq_rc=0,status=0;
    c80_stage(io,r,19); r->mask_main_ready=c80_read(io,C80_MASK);
    r->runtime_glo_before=c80_read(io,C80_GLO);
    if(r->runtime_glo_before==0xffffffffu) return C80_MODE_REFUSED;
    /* Actual OEM leaves download mode before runtime commands. No scheduler,
     * RF, calibration, MAC TX/RX enable or other hardware setup is added. */
    c80_write(io,C80_GLO,r->runtime_glo_before&~C80_DOWNLOAD_MODE);
    r->runtime_glo_after=c80_read(io,C80_GLO);
    if(r->runtime_glo_after==0xffffffffu || (r->runtime_glo_after&C80_DOWNLOAD_MODE))
        return C80_MODE_REFUSED;
    r->mask_runtime=c80_read(io,C80_MASK); c80_stage(io,r,20);
    for(i=0;i<sizeof(body);++i) body[i]=0;
    c80_put16(body,5); body[4]=0; body[5]=1; c80_put32(body+8,1);
    /* Linux always supplies both callbacks. Native legacy transport fault
     * cases may omit both to isolate the already-proven polling contract. */
    if(!!io->irq_arm!=!!io->irq_disarm) return C80_IRQ_BAD;
    if(io->irq_arm) {
        rc=io->irq_arm(io->context,r);
        if(rc) { io->irq_disarm(io->context,r); return rc; }
    }
    r->counter_query_attempted=1;
    rc=c80_exchange(io,r,0xed,body,sizeof(body),&status);
    if(io->irq_disarm) irq_rc=io->irq_disarm(io->context,r);
    if(rc) return rc;
    if(irq_rc) return irq_rc;
    return r->counter_query_valid?0:C80_QUERY_BAD;
}
static c80_u32 c80_nvm_snapshot(struct c80_io *io,struct c80_result *r)
{
    c80_u32 i,rc;
    r->nvm_attempted=1;
    rc=io->nvm_read(io->context,io->pool->nvm_payload+4,C80_NVM_BYTES,&r->nvm_radio_crc);
    if(rc || r->nvm_radio_crc!=C80_RADIO_CRC ||
       c80_get16(io->pool->nvm_payload+4)!=0x7626) return C80_NVM_BAD_SOURCE;
    r->nvm_raw_crc=c80_crc(io->pool->nvm_payload+4,C80_NVM_BYTES);
    for(i=C80_NVM_COPY_BYTES;i<C80_NVM_BYTES;++i) io->pool->nvm_payload[4+i]=0;
    r->nvm_upload_crc=c80_crc(io->pool->nvm_payload+4,C80_NVM_BYTES);
    io->pool->nvm_payload[0]=1; io->pool->nvm_payload[1]=1;
    c80_put16(io->pool->nvm_payload+2,C80_NVM_BYTES);
    r->nvm_valid=1; return 0;
}
static c80_u32 c80_nvm_roundtrip(struct c80_io *io,struct c80_result *r)
{
    c80_u8 body[6]; c80_u32 rc,status=0;
    c80_stage(io,r,21); r->nvm_set_attempted=1;
    rc=c80_exchange(io,r,0xed,io->pool->nvm_payload,4+C80_NVM_BYTES,&status);
    if(rc) return rc;
    if(!r->nvm_set_valid || status) return C80_NVM_SET_REJECTED;
    c80_stage(io,r,22); r->nvm_get_attempted=1;
    body[0]=1; body[1]=1; c80_put16(body+2,0); c80_put16(body+4,C80_NVM_BYTES);
    rc=c80_exchange(io,r,0xed,body,sizeof(body),&status);
    if(rc) return rc;
    return r->nvm_get_valid && r->nvm_equal?0:C80_NVM_BAD_REPLY;
}
static c80_u32 c80_devinfo_mac(struct c80_io *io,struct c80_result *r)
{
    const c80_u8 *mac=io->pool->nvm_payload+8; c80_u32 i,any=0,all=255;
    if(!r->nvm_valid) return C80_DEVINFO_BAD_MAC;
    for(i=0;i<6;++i) { any|=mac[i]; all&=mac[i]; }
    if(!any || all==255 || (mac[0]&1)) return C80_DEVINFO_BAD_MAC;
    r->devinfo_mac_valid=1; return 0;
}
/* A second window without SYNC/beacon commands isolates the RAM16 loss of
 * WPDMA enables. Readbacks establish when a prerequisite first disappears;
 * they cannot identify a firmware crash, sleep transition or RF failure.
 * Busy bits1/3 are transient and deliberately not failure criteria. */
static c80_u32 c80_watch_sample(struct c80_io *io,struct c80_hif_sample *s)
{
    c80_u32 bad=0;
    s->glo=c80_read(io,C80_GLO); s->own=c80_read(io,C80_OWN);
    s->sync=c80_read(io,C80_SYNC); s->source=c80_read(io,C80_SOURCE);
    s->mask=c80_read(io,C80_MASK); s->tx_cpu=c80_read(io,0x180043f8);
    s->tx_dma=c80_read(io,0x180043fc); s->rx0_dma=c80_read(io,0x1800440c);
    s->rx1_dma=c80_read(io,0x1800441c);
    if(!(s->glo&1)) bad|=1;
    if(!(s->glo&4)) bad|=2;
    if(s->glo==0xffffffffu || s->own==0xffffffffu || s->sync==0xffffffffu) bad|=4;
    if(s->own&1) bad|=8;
    if((s->sync&14)!=6) bad|=16;
    if(s->glo&C80_DOWNLOAD_MODE) bad|=32;
    return bad;
}
/* Exact OEM4031bb30 mapping followed by4031bc6c MAC-read, not legacy
 * offset comments from other silicon. Fields are raw/non-atomic; MIB may
 * clear on read or be maintained by firmware, so do not subtract snapshots. */
static const c80_u32 c80_state_regs[12]={0x18023080,0x18023110,0x18023130,
    0x1802b010,0x1802b034,0x1802b030,0x1802b05c,0x18024000,
    0x1802d000,0x1802d008,0x1802d010,0x180080b0};
static c80_u32 c80_state_capture(struct c80_io *io,struct c80_result *r,c80_u32 index)
{
    struct c80_hif_sample guard; c80_u32 i,bad;
    if(!io->beacon_state_test) return 0;
    if(index>=5 || !r->main_ready || !r->radio_valid[3] || r->radio_status[3]) return C80_STATE_BAD_PREREQ;
    bad=c80_watch_sample(io,&guard);
    if(bad) { r->state_guard_fault=bad; return C80_HIF_CHANGED; }
    r->state_us[index]=io->time_us(io->context); r->state_phase[index]=r->phase;
    for(i=0;i<12;++i) {
        r->state_regs[index][i]=c80_read(io,c80_state_regs[i]);
        if(r->state_regs[index][i]==0xffffffffu) r->state_allones[index]|=1u<<i;
    }
    r->state_mask|=1u<<index; return 0;
}
static c80_u32 c80_state_tsf(struct c80_io *io,struct c80_result *r,c80_u32 index)
{
    c80_u8 body[104]; c80_u32 i,rc,status=~0u; c80_u64 before,after;
    if(!io->beacon_state_test) return 0;
    if(index>=2) return C80_STATE_BAD_PREREQ;
    for(i=0;i<104;++i) body[i]=0;
    c80_put16(body,2); /* OEM4031469c: TSF category2, OwnMac0 at body+4. */
    c80_stage(io,r,39+index); r->tsf_attempted[index]=1;
    rc=c80_exchange(io,r,0xed,body,104,&status);
    if(rc) return rc;
    if(!r->tsf_valid[index]) return C80_TSF_BAD_REPLY;
    r->tsf_observed_us[index]=io->time_us(io->context);
    if(index && r->tsf_valid[0]) {
        before=((c80_u64)r->tsf_high[0]<<32)|r->tsf_low[0];
        after=((c80_u64)r->tsf_high[1]<<32)|r->tsf_low[1];
        if(after>=before) { r->tsf_delta_valid=1; r->tsf_delta_us=after-before; }
    }
    return 0; /* Zero/stationary/backwards TSF is diagnostic data, not failure. */
}
static c80_u32 c80_watch_window(struct c80_io *io,struct c80_result *r,c80_u32 index)
{
    struct c80_watch_window *w=&r->watch[index];
    c80_u64 start=io->time_us(io->context),now; c80_u32 i,rc,status=0,slot;
    w->started=1;
    if(index==1 && io->assoc_reply_test) r->assoc_window_start_us=start;
    for(i=0;i<=30000;++i) {
        now=io->time_us(io->context);
        if(now<start) return C80_BAD_TIMER;
        w->elapsed_us=now-start>0xffffffffu?0xffffffffu:(c80_u32)(now-start);
        w->fault_bits=c80_watch_sample(io,&w->last); ++w->samples;
        if(i==0) w->before=w->last;
        if(w->fault_bits) {
            r->watch_fault_phase=r->phase;
            slot=r->command_submitted?r->command_submitted-1:0;
            /* Reference the LAST published command, not a newly sent packet. */
            c80_transport_snapshot(io,r,15,slot,&io->pool->tx[slot]);
            return C80_HIF_CHANGED;
        }
        w->last_good_us=w->elapsed_us;
        rc=c80_receive(io,r,0,0,&status);
        if(rc!=C80_RX_TIMEOUT) return rc?rc:C80_BEACON_BAD_REPLY;
        if(index==1) { rc=c80_auth_poll(io,r);if(rc) return rc;rc=c80_assoc_step(io,r);if(rc) return rc;rc=c80_data_step(io,r);if(rc) return rc; }
        if(w->elapsed_us>=30000000) {
            if(index==1 && io->data_echo_test) {
                c80_u32 k;
                for(k=0;k<2;++k) if(r->diag_captured[k] && (!r->diag_submitted[k] || !r->diag_dma_done[k] || !r->diag_token_returned[k])) return C80_DATA_TIMEOUT;
            }
            if(index==1 && io->auth_reply_test && r->auth_submitted && !r->auth_dma_done) return C80_AUTH_TIMEOUT;
            if(index==1 && io->assoc_reply_test && r->assoc_captured &&
               (!r->assoc_submitted || !r->assoc_dma_done || !r->assoc_token_returned)) return C80_ASSOC_TIMEOUT;
            w->complete=1; return 0;
        }
        if(i<30000) io->delay_us(io->context,1000);
    }
    return C80_BAD_TIMER; /* iteration cap also bounds a frozen clock */
}
/* Exact OEM4031a734->403199fc 32B TXD for band0/OwnMac0/WCID0,
 * CCK1Mbps/20MHz/noACK beacon. Frame fields are standard802.11; MACs from
 * validated ROMNVM only. No template/SSID/client configuration API added. */
static c80_u32 c80_beacon_roundtrip(struct c80_io *io,struct c80_result *r)
{
    /* OEM4031a734 WDEV+86c=2 (FW beacon):pkt_ft=3,subtype8/type0.
     * Prior zero-method context incorrectly selected HIF cut-through. */
    static const c80_u8 txd[32]={0x5e,0x00,0x00,0x48,0x00,0xcc,0x00,0x03,0x08,0x04,0x00,0xa0,0x01,0xf8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x08,0x00};
    static const c80_u8 frame[62]={0x80,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x01,0x00,0x00,0x09,0x43,0x38,0x30,0x2d,0x52,0x41,0x4d,0x31,0x36,0x01,0x04,0x82,0x84,0x8b,0x96,0x03,0x01,0x06,0x05,0x04,0x00,0x01,0x00,0x00};
    c80_u8 *body=io->pool->beacon_body; c80_u32 k,i,n,rc,status=~0u,polls;
    c80_u64 start,now;
    if(!r->nvm_equal || !r->devinfo_valid[0] || r->devinfo_status[0] ||
       !r->bss_valid[0] || r->bss_status[0]) return C80_BEACON_BAD_STATE;
    for(i=0;i<4;++i) if(!r->radio_valid[i] || r->radio_status[i]) return C80_BEACON_BAD_STATE;
    rc=c80_state_capture(io,r,0); if(rc) return rc;
    if(io->watch_test) {
        c80_stage(io,r,38);
        rc=c80_watch_window(io,r,0);
        if(rc) return rc; /* Never enable beacon after a failed control window. */
    }
    for(k=0;k<4;++k) {
        for(i=0;i<528;++i) body[i]=0;
        if(k==0 || k==3) {
            c80_put16(body+2,1); body[4]=1; c80_put16(body+8,9); c80_put16(body+10,16);
            if(k==0) { c80_put16(body+12,100); body[14]=1; body[15]=1; }
            n=24;
        } else {
            body[1]=k==1; c80_put16(body+8,94); c80_put16(body+10,88);
            for(i=0;i<32;++i) body[12+i]=txd[i];
            for(i=0;i<62;++i) body[44+i]=frame[i];
            for(i=0;i<6;++i) body[54+i]=body[60+i]=io->pool->nvm_payload[8+i];
            n=528;
        }
        c80_stage(io,r,33+k); r->beacon_attempted[k]=1;
        rc=c80_exchange(io,r,0xed,body,n,&status);
        if(rc) return rc;
        if(!r->beacon_valid[k] || status) return C80_BEACON_REJECTED;
        if(k==0 || k==3) { rc=c80_state_capture(io,r,k==0?1:4); if(rc) return rc; }
        if(k==1) {
            rc=c80_state_capture(io,r,2); if(rc) return rc;
            rc=c80_state_tsf(io,r,0); if(rc) return rc;
            c80_stage(io,r,37); r->beacon_window_started=1;
            if(io->watch_test) {
                rc=c80_watch_window(io,r,1);
                r->beacon_window_us=r->watch[1].elapsed_us;
                r->beacon_window_polls=r->watch[1].samples?r->watch[1].samples-1:0;
                if(rc) return rc;
                if(io->assoc_reply_test && r->sta_attempted[0]) {
                    rc=c80_sta_exchange(io,r,1);if(rc) return rc;
                    r->assoc_complete=r->assoc_dma_done && r->assoc_token_returned;
                }
                rc=c80_state_capture(io,r,3); if(rc) return rc;
                rc=c80_state_tsf(io,r,1); if(rc) return rc;
                continue;
            }
            start=io->time_us(io->context);
            for(polls=0;polls<30000;++polls) {
                now=io->time_us(io->context);
                if(now<start) return C80_BAD_TIMER;
                if(now-start>=30000000) break;
                rc=c80_receive(io,r,0,0,&status);
                if(rc!=C80_RX_TIMEOUT) return rc?rc:C80_BEACON_BAD_REPLY;
                io->delay_us(io->context,1000);
            }
            now=io->time_us(io->context); if(now<start) return C80_BAD_TIMER;
            r->beacon_window_us=now-start>0xffffffffu?0xffffffffu:(c80_u32)(now-start);
            r->beacon_window_polls=polls;
            if(r->beacon_window_us<30000000) return C80_BAD_TIMER;
        }
    }
    r->beacon_complete=1; return 0;
}
/* Five packets proven against OEM builders: MAC OFF,channel6 HT20,
 * 1x1 path,MAC ON,MAC OFF. Keep BSS/device contexts alive until completed.
 * No beacon/sync/STA-record/data TX or radio05 command. */
static c80_u32 c80_radio_roundtrip(struct c80_io *io,struct c80_result *r)
{
    static const c80_u32 phases[5]={27,28,29,30,32};
    c80_u8 body[76]; c80_u32 step,i,bytes,rc,status=~0u,polls;
    c80_u64 start,now;
    if(!r->nvm_equal || !r->devinfo_valid[0] || r->devinfo_status[0] ||
       !r->bss_valid[0] || r->bss_status[0]) return C80_RADIO_BAD_STATE;
    for(step=0;step<5;++step) {
        for(i=0;i<sizeof(body);++i) body[i]=0;
        bytes=4;
        if(step==1 || step==2) {
            body[0]=6; body[1]=6; body[3]=1; body[4]=1; bytes=76;
            /* OEM channel builder fills its49 per-rate entries with0x3f.
             * This is the factory command field, not a dBm power override. */
            if(step==1) for(i=20;i<69;++i) body[i]=0x3f;
        } else if(step==3) body[0]=1;
        c80_stage(io,r,phases[step]); r->radio_attempted[step]=1;
        rc=c80_exchange(io,r,0xed,body,bytes,&status);
        if(rc) return rc;
        if(!r->radio_valid[step] || status) return C80_RADIO_REJECTED;
        if(step==3 && io->beacon_test) {
            rc=c80_beacon_roundtrip(io,r);
            if(rc) return rc;
        } else if(step==3) {
            c80_stage(io,r,31); r->radio_listen_started=1;
            start=io->time_us(io->context);
            for(polls=0;polls<500;++polls) {
                now=io->time_us(io->context);
                if(now<start) return C80_BAD_TIMER;
                if(now-start>=500000 || r->radio_rx_full) break;
                rc=c80_receive(io,r,0,0,&status);
                if(rc!=C80_RX_TIMEOUT) return rc?rc:C80_RADIO_BAD_REPLY;
                io->delay_us(io->context,1000);
            }
            now=io->time_us(io->context); if(now<start) return C80_BAD_TIMER;
            r->radio_listen_us=now-start>0xffffffffu?0xffffffffu:(c80_u32)(now-start);
            r->radio_listen_polls=polls;
            if(r->radio_listen_us<500000 && !r->radio_rx_full) return C80_BAD_TIMER;
        }
    }
    r->radio_complete=1; return 0;
}
static c80_u32 c80_bss_roundtrip(struct c80_io *io,struct c80_result *r)
{
    c80_u8 body[52]; c80_u32 step,i,offset,bytes,rc,status=~0u;
    if(!r->nvm_equal || !r->devinfo_valid[0] || r->devinfo_status[0])
        return C80_BSS_BAD_STATE;
    for(step=0;step<2;++step) {
        for(i=0;i<sizeof(body);++i) body[i]=0;
        c80_put16(body+2,step?1:2); body[4]=1; offset=8;
        if(!step) {
            /* OWN mapping tag0: hardwareBSS0/OwnMac0/Band0,
             * CONNECTION_INFRA_AP=0x10002. Actual handler402eca04. */
            c80_put16(body+offset,0); c80_put16(body+offset+2,16);
            c80_put32(body+offset+8,0x10002); offset+=16;
        }
        /* BASIC tag1: normal AP initializer403606f8 copies configured
         * period/DTIM into args+76/+78;402ecb94 serializes them. The narrow
         * diagnostic AP helper4031d708 zeroed these fields in older probes.
         * Match the unchanged beacon/SYNC100TU/DTIM1 in this Linux trial.
         * NETWORK_INFRA/cipher1/BMC/WMM/PHY and all other fields unchanged. */
        c80_put16(body+offset,1); c80_put16(body+offset+2,28);
        c80_put32(body+offset+4,0x10000); body[offset+8]=step==0;
        for(i=0;i<6;++i) body[offset+12+i]=io->pool->nvm_payload[8+i];
        body[offset+21]=1; bytes=offset+28;
        if(io->bss_period_test) { c80_put16(body+offset+10,100);body[offset+19]=1; }
        r->bss_period[step]=c80_get16(body+offset+10);r->bss_dtim[step]=body[offset+19];
        c80_stage(io,r,25+step); r->bss_attempted[step]=1;
        rc=c80_exchange(io,r,0xed,body,bytes,&status);
        if(rc) return rc;
        if(!r->bss_valid[step] || status) return C80_BSS_REJECTED;
        if(!step && io->radio_test) {
            rc=c80_radio_roundtrip(io,r);
            if(rc) return rc;
        }
    }
    r->bss_complete=1; return 0;
}
static c80_u32 c80_devinfo_roundtrip(struct c80_io *io,struct c80_result *r)
{
    c80_u8 body[20]={0}; c80_u32 i,step,rc,status=~0u;
    if(!r->nvm_equal || !r->devinfo_mac_valid) return C80_DEVINFO_BAD_MAC;
    /* OEM TPOS header byte1 is reserved/zero; band0 is in the active TLV.
     * One device context, OwnMac0, band0; no MAC TX/RX or RF commands. */
    c80_put16(body+2,1); body[4]=1;
    c80_put16(body+8,0); c80_put16(body+10,12);
    for(i=0;i<6;++i) body[14+i]=io->pool->nvm_payload[8+i];
    for(step=0;step<2;++step) {
        body[12]=step==0; c80_stage(io,r,23+step); r->devinfo_attempted[step]=1;
        rc=c80_exchange(io,r,0xed,body,sizeof(body),&status);
        if(rc) return rc;
        if(!r->devinfo_valid[step] || status) return C80_DEVINFO_REJECTED;
        if(!step && io->bss_test) {
            rc=c80_bss_roundtrip(io,r);
            if(rc) return rc;
        }
    }
    r->devinfo_complete=1; return 0;
}
static void c80_cleanup(struct c80_io *io,struct c80_result *r)
{
    c80_u32 v,i,j;
    c80_stage(io,r,90);
    if(r->dma_cfg_touched) {
        /* The entire host mask was verified0 before this experiment owns
         * the rings/engine. OEM IRQ-disable writes0 to this R/W register.
         * Mask before stopping, then again after MCU/DMA are quiescent;
         * record every observed value rather than ignoring a changed bit. */
        r->mask_cleanup_entry=c80_read(io,C80_MASK);
        c80_write(io,C80_MASK,0); ++r->mask_zero_writes;
        r->mask_first_zero=c80_read(io,C80_MASK);
        v=c80_read(io,C80_GLO); c80_write(io,C80_GLO,v&~5u);
    }
    if(r->mcu_released) {
        v=c80_read(io,C80_RESET);
        c80_write(io,C80_RESET,(v&0xffffff)|0x88001000);
        if(!c80_poll(io,C80_RESET,0x1000,0x1000,20000,0)) {
            r->critical=C80_CRITICAL_RESET; return;
        }
        r->mcu_stopped=1; io->delay_us(io->context,2000);
    }
    if(r->dma_cfg_touched) {
        if(!c80_poll(io,C80_GLO,15,0,200000,0)) {
            r->critical=C80_CRITICAL_DMA; return;
        }
        r->dma_idle=1;
        r->mask_after_stop=c80_read(io,C80_MASK);
    }
    /* Read-only DMA indices cannot be restored by ordinary register writes.
     * Restore programmed controls only, retain masked IRQ source; require fresh boot. */
    if(r->rings_touched) for(i=0;i<4;++i) for(j=0;j<3;++j)
        c80_write(io,c80_ring_regs[i]+4*j,r->rings_before[i][j]);
    if(r->auth_ring_touched) for(i=0;i<3;++i) c80_write(io,C80_AUTH_RING+4*i,r->auth_ring_before[i]);
    if(r->dma_cfg_touched) c80_write(io,C80_GLO,r->glo_before);
    for(i=3;i;i--) if(r->controls_touched&(1u<<(i-1))) {
        v=c80_read(io,c80_controls[i-1]);
        c80_write(io,c80_controls[i-1],(v&~c80_control_masks[i-1])|
            (r->controls_before[i-1]&c80_control_masks[i-1]));
    }
    for(i=0;i<3;++i) {
        r->controls_after[i]=c80_read(io,c80_controls[i]);
        r->control_diff[i]=r->controls_after[i]^r->controls_before[i];
        /* Restore/check exactly the bits this test owns. The MCU/hardware
         * changes other fields in18002150 during the real command path.
         * Preserve and report those fields; do not force an old full word. */
        if((r->controls_touched&(1u<<i)) &&
           (r->control_diff[i]&c80_control_masks[i])) {
            r->controls_owned_bad|=1u<<i;
            r->cleanup_flags|=C80_CLEANUP_CONTROL;
        }
        if(r->control_diff[i]&~c80_control_masks[i]) r->controls_other_changed|=1u<<i;
    }
    if(r->ready) {
        /* Keep the final mask write after restoring GLO/owned controls too:
         * stopping/resetting or restoring a control may change this mask. */
        if(r->dma_cfg_touched) {
            r->mask_before_final_zero=c80_read(io,C80_MASK);
            c80_write(io,C80_MASK,0); ++r->mask_zero_writes;
        }
        r->glo_after=c80_read(io,C80_GLO); r->mask_after=c80_read(io,C80_MASK);
        r->source_after=c80_read(io,C80_SOURCE);
        if((r->dma_cfg_touched || r->rings_touched) && (r->glo_after&15)) {
            r->critical=C80_CRITICAL_DMA; return;
        }
        if(r->dma_cfg_touched && r->glo_after!=r->glo_before) r->cleanup_flags|=C80_CLEANUP_GLO;
        if(r->dma_cfg_touched && r->mask_after!=r->mask_before) r->cleanup_flags|=C80_CLEANUP_MASK;
    }
    for(i=0;i<10;++i) r->aon_after[i]=c80_read(io,c80_aon_regs[i]);
    if(r->rings_touched) for(i=0;i<4;++i) for(j=0;j<4;++j) {
        r->rings_after[i][j]=c80_read(io,c80_ring_regs[i]+4*j);
        if(j<3 && r->rings_after[i][j]!=r->rings_before[i][j]) {
            r->rings_restore_bad|=1u<<(i*3+j); r->cleanup_flags|=C80_CLEANUP_RING;
        }
    }
    if(r->auth_ring_touched) for(i=0;i<4;++i) {
        r->auth_ring_after[i]=c80_read(io,C80_AUTH_RING+4*i);
        if(i<3 && r->auth_ring_after[i]!=r->auth_ring_before[i]) { r->auth_ring_restore_bad|=1u<<i;r->cleanup_flags|=C80_CLEANUP_RING; }
    }
    r->cleanup=!!r->cleanup_flags;
}
static c80_u32 c80_run(struct c80_io *io,const struct c80_blob *fw,
                       struct c80_result *r)
{
    c80_u32 i,j,v,rc=0,programmed[4][3]; c80_u64 start;
    c80_stage(io,r,1);
    if(io->data_echo_test && !io->assoc_reply_test) { r->primary=C80_DATA_BAD_PREREQ;return r->primary; }
    if(io->assoc_reply_test && (!io->auth_reply_test || !io->rx1_packet_test)) { r->primary=C80_ASSOC_BAD_PREREQ;return r->primary; }
    if(io->auth_reply_test && (!io->management_rx_test || !io->rx1_rearm_test || !io->bss_period_test || !io->beacon_state_test ||
       !io->rx0_rearm_test || !io->watch_test || !io->beacon_test || !io->radio_test || !io->devinfo_test || !io->bss_test)) {
        r->primary=C80_AUTH_BAD_PREREQ;return r->primary;
    }
    if(io->beacon_state_test && (!io->beacon_test || !io->watch_test || !io->rx0_rearm_test)) {
        r->primary=C80_STATE_BAD_PREREQ; return C80_STATE_BAD_PREREQ;
    }
    if(io->bss_period_test && (!io->beacon_state_test || !io->radio_test || !io->bss_test || !io->devinfo_test)) {
        r->primary=C80_BSS_PERIOD_BAD_PREREQ; return r->primary;
    }
    if(io->rx1_packet_test && (!io->rx1_rearm_test || !io->radio_test)) { r->primary=C80_RX1_BAD_PREREQ;return r->primary; }
    if(io->rx1_rearm_test && (!io->radio_test || !io->rx0_rearm_test)) {
        r->primary=C80_RX1_BAD_PREREQ;return r->primary;
    }
    if(io->management_rx_test && (!io->rx1_rearm_test || !io->beacon_state_test || !io->bss_period_test || !io->beacon_test || !io->bss_test || !io->devinfo_test)) {
        r->primary=C80_MGMT_BAD_PREREQ;return r->primary;
    }
    if(io->rx0_rearm_test && !io->radio_test) {
        r->primary=C80_RADIO_BAD_STATE; return C80_RADIO_BAD_STATE;
    }
    if(io->watch_test && !io->beacon_test) {
        r->primary=C80_BEACON_BAD_STATE; return C80_BEACON_BAD_STATE;
    }
    if(io->beacon_test && (!io->radio_test || !io->devinfo_test || !io->bss_test)) {
        r->primary=C80_BEACON_BAD_STATE; return r->primary;
    }
    if(io->radio_test && (!io->devinfo_test || !io->bss_test)) {
        r->primary=C80_RADIO_BAD_STATE; return r->primary;
    }
    if(io->bss_test && !io->devinfo_test) {
        r->primary=C80_BSS_BAD_STATE; return C80_BSS_BAD_STATE;
    }
    for(i=0;i<6;++i) if(!fw[i].data || fw[i].bytes!=c80_blob_sizes[i] ||
       c80_crc(fw[i].data,fw[i].bytes)!=c80_blob_crcs[i]) { r->primary=C80_BAD_FW; return C80_BAD_FW; }
    start=io->time_us(io->context); io->delay_us(io->context,10);
    if(io->time_us(io->context)<=start) { r->primary=C80_BAD_TIMER; return C80_BAD_TIMER; }
    for(i=0;i<10;++i) r->aon_before[i]=c80_read(io,c80_aon_regs[i]);
    if((r->aon_before[0]&0x8104) || (r->aon_before[1]&0x8104) ||
       (r->aon_before[2]&7) || (r->aon_before[3]&7) ||
       (r->aon_before[4]&0xfff)!=0x40 || !(r->aon_before[5]&1) ||
       (r->aon_before[6]&0x20800000)!=0x20800000 ||
       r->aon_before[7]!=r->aon_before[8] ||
       (r->aon_before[7]&0x07000000)!=0x07000000 ||
       (r->aon_before[9]&0x1200)!=0x1000) { r->primary=C80_BAD_AON; return C80_BAD_AON; }
    c80_stage(io,r,2);
    if(c80_read(io,0x180b1010)!=0x10040101 || c80_read(io,0x180b101c)&15 ||
       (c80_read(io,0x18002000)&0xffff)!=0x8a00 ||
       (c80_read(io,0x18002004)&0xffff)!=0x8a00) { r->primary=C80_BAD_ID; return C80_BAD_ID; }
    if(c80_read(io,0x18002600)==0x1d1e) { r->primary=C80_STALE; return C80_STALE; }
    /* Snapshot/validate board NVM before MCU release or peripheral writes.
     * Linux always supplies the ROM MTD reader. Legacy native fault cases
     * may omit it to isolate the already hardware-proven transport path. */
    if(io->nvm_read) {
        rc=c80_nvm_snapshot(io,r);
        if(rc) { r->primary=rc; return rc; }
    }
    if(io->devinfo_test) {
        rc=c80_devinfo_mac(io,r);
        if(rc) { r->primary=rc; return rc; }
    }
    for(i=0;i<3;++i) r->controls_before[i]=c80_read(io,c80_controls[i]);
    c80_stage(io,r,3);
    for(i=0;i<2;++i) {
        io->copy_emi(io->context,c80_blob_offsets[i],fw[i].data,fw[i].bytes);
        if(io->crc_emi(io->context,c80_blob_offsets[i],fw[i].bytes)!=c80_blob_crcs[i]) {
            rc=C80_BAD_FW; goto done;
        }
    }
    for(i=0;i<3;++i) {
        r->controls_touched|=1u<<i;
        c80_write(io,c80_controls[i],r->controls_before[i]|c80_control_masks[i]);
        if((c80_read(io,c80_controls[i])&c80_control_masks[i])!=c80_control_masks[i]) {
            rc=C80_BOOT_CONTROL; goto done;
        }
    }
    v=c80_read(io,C80_RESET); r->mcu_released=1;
    c80_write(io,C80_RESET,((v&0xffffff)&~0x1000u)|0x88000000);
    if(c80_read(io,C80_RESET)&0x1000) { rc=C80_BOOT_CONTROL; goto done; }
    c80_stage(io,r,4);
    if(!c80_poll(io,0x18002600,~0u,0x1d1e,2000000,0)) { rc=C80_READY_TIMEOUT; goto done; }
    r->ready=1; r->own_before=c80_read(io,C80_OWN);
    if(r->own_before==0xffffffffu) { rc=C80_OWN_TIMEOUT; goto done; }
    if(r->own_before&1) { c80_write(io,C80_OWN,2); r->own_sent=1; }
    if(!c80_poll(io,C80_OWN,1,0,2000000,&r->own_last)) { rc=C80_OWN_TIMEOUT; goto done; }
    r->glo_before=c80_read(io,C80_GLO); r->mask_before=c80_read(io,C80_MASK);
    if(r->glo_before==0xffffffffu || (r->glo_before&15) || r->mask_before) {
        rc=C80_BAD_DMA; goto done;
    }
    c80_stage(io,r,5);
    /* Match OEM ordering: main EMI copies AFTER initial MCU/HIF ownership.
     * Linux maps reserved EMI without a cacheable linear alias. */
    for(i=2;i<4;++i) {
        io->copy_emi(io->context,c80_blob_offsets[i],fw[i].data,fw[i].bytes);
        r->main_crc[i-2]=io->crc_emi(io->context,c80_blob_offsets[i],fw[i].bytes);
        if(r->main_crc[i-2]!=c80_blob_crcs[i]) { rc=C80_MAIN_CRC; goto done; }
    }
    c80_stage(io,r,6);
    /* Global enable applies to every TX queue, including FWDL3. Refuse
     * inherited descriptors on any other queue before enabling the engine. */
    for(i=0;i<16;++i) if(c80_read(io,0x18004304+i*16)) {
        rc=C80_RINGS_CONFIGURED; goto done;
    }
    for(i=0;i<4;++i) for(j=0;j<4;++j) {
        r->rings_before[i][j]=c80_read(io,c80_ring_regs[i]+4*j);
        if(r->rings_before[i][j]) { rc=C80_RINGS_CONFIGURED; goto done; }
    }
    if(io->auth_reply_test) {
        for(i=0;i<4;++i) { r->auth_ring_before[i]=c80_read(io,C80_AUTH_RING+4*i);if(r->auth_ring_before[i]) { rc=C80_AUTH_RING_BASELINE;goto done; } }
        r->auth_ring_saved=1;
        for(i=0;i<C80_AUTH_N;++i) io->pool->auth_tx[i].ctrl=C80_DONE;
    }
    for(i=0;i<C80_TX_N;++i) { io->pool->tx[i].ctrl=C80_DONE; io->pool->fwdl[i].ctrl=C80_DONE; }
    for(i=0;i<2;++i) for(j=0;j<C80_RX_N;++j) {
        io->pool->rx[i][j].addr=c80_dma_address(io,io->pool->data[i][j]);
        io->pool->rx[i][j].ctrl=C80_RX_SIZE<<16;
    }
    r->rings_touched=1;
    programmed[0][0]=c80_dma_address(io,io->pool->tx);
    programmed[0][1]=C80_TX_N; programmed[0][2]=0;
    for(i=0;i<2;++i) {
        programmed[i+1][0]=c80_dma_address(io,io->pool->rx[i]);
        programmed[i+1][1]=C80_RX_N; programmed[i+1][2]=C80_RX_N-1;
    }
    programmed[3][0]=c80_dma_address(io,io->pool->fwdl);
    programmed[3][1]=C80_TX_N; programmed[3][2]=0;
    for(i=0;i<4;++i) for(j=0;j<3;++j)
        c80_write(io,c80_ring_regs[i]+4*j,programmed[i][j]);
    for(i=0;i<4;++i) for(j=0;j<3;++j)
        if(c80_read(io,c80_ring_regs[i]+4*j)!=programmed[i][j]) {
            rc=C80_RING_PROGRAM; goto done;
        }
    if(io->auth_reply_test) {
        c80_u32 auth_programmed[3]={c80_dma_address(io,io->pool->auth_tx),C80_AUTH_N,0};
        r->auth_ring_touched=1;
        for(i=0;i<3;++i) c80_write(io,C80_AUTH_RING+4*i,auth_programmed[i]);
        for(i=0;i<3;++i) if(c80_read(io,C80_AUTH_RING+4*i)!=auth_programmed[i]) { rc=C80_AUTH_RING_PROGRAM;goto done; }
        r->auth_ring_programmed=1;
    }
    if(c80_read(io,C80_MASK) || (c80_read(io,C80_GLO)&15)) {
        rc=C80_BAD_DMA; goto done;
    }
    io->dma_order(io->context,1); r->dma_cfg_touched=1;
    c80_write(io,C80_GLO,r->glo_before|0xc45); r->dma_started=1;
    if((c80_read(io,C80_GLO)&0xc45)!=0xc45) { rc=C80_BAD_DMA; goto done; }
    /* OEM40308dd0 enables GLO bit9 around both patch/main dispatchers.
     * RAM5 omitted it. Keep the hardware-proven TX15 command / FWDL3 data
     * paths; do not import another chip's scheduler/credit configuration.
     * Cleanup first stops MCU/DMA, then restores the exact saved GLO value. */
    c80_write(io,C80_GLO,c80_read(io,C80_GLO)|C80_DOWNLOAD_MODE);
    r->download_enable_glo=c80_read(io,C80_GLO);
    r->download_mode_checked=1;
    if(!c80_download_mode(io,r)) { rc=C80_MODE_REFUSED; goto done; }
    rc=c80_patch(io,r,&fw[4]);
    if(!rc) rc=c80_main_firmware(io,r,&fw[5]);
    if(!rc) rc=c80_runtime_query(io,r);
    if(!rc && r->nvm_valid) rc=c80_nvm_roundtrip(io,r);
    if(!rc && io->devinfo_test) rc=c80_devinfo_roundtrip(io,r);
done:
    r->primary=rc; c80_cleanup(io,r);
    return r->critical?r->critical:r->cleanup?C80_RESTORE:rc;
}
#endif
