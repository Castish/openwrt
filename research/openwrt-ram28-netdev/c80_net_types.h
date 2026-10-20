/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_NET_TYPES_H
#define C80_NET_TYPES_H
/* Each published header, payload and token is used once in this boot.
 * The 512-cell ring matches the OEM capacity; no descriptor wraps in this
 * 256-packet experiment. Both management cells keep their original data. */
#define C80_NET_RING_N 512u
#define C80_NET_TX_N 256u
#define C80_NET_TOKEN_BASE 16u
#define C80_NET_MTU 1400u
#define C80_NET_ETH_MAX (14u+C80_NET_MTU)
#define C80_NET_FRAME_MAX 1440u
#define C80_NET_SUBMITTED 1u
#define C80_NET_HEADER_DONE 2u
#define C80_NET_RETURNED 4u
struct c80_net_cell {
    c80_u8 header[64];
    c80_u8 frame[C80_NET_FRAME_MAX];
} __attribute__((aligned(16)));
struct c80_net_pool {
    struct c80_net_cell tx[C80_NET_TX_N];
    /* CPU-only conversion scratch, never referenced by a DMA descriptor. */
    c80_u8 ethernet[C80_NET_ETH_MAX];
};
struct c80_net_result {
    c80_u32 enabled,prepared,linked,closed,exhausted,stop_requested;
    c80_u32 submitted,headers,returned,completed,inflight;
    c80_u32 early_tokens,duplicate_tokens,tx_rejected;
    c80_u32 rx_seen,rx_raw,rx_translated,rx_bad_length,rx_bad_format;
    c80_u32 rx_bad_status,rx_wrong_peer,rx_bad_protocol,rx_duplicate;
    c80_u32 rx_delivered,rx_dropped,rx_arp,rx_ipv4;
    c80_u32 last_ctrl,last_cpu,last_dma,last_slot,last_wait_us;
    c80_u32 last_seq,last_tid,seq_valid;
    c80_u8 token[C80_NET_TX_N];
    c80_u32 ethernet_bytes[C80_NET_TX_N];
    c80_u64 submitted_us;
};
#endif
