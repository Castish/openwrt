/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_PDMA_CORE_H
#define C80_PDMA_CORE_H

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This experimental driver requires the verified little-endian target"
#endif

#define C80_TX_COUNT 64u
#define C80_RX_COUNT 128u
#define C80_BUFFER_SIZE 2048u
#define C80_DDONE (1u << 31)
#define C80_LAST (1u << 30)
#define C80_TX_PORT1 (1u << 25)
#define C80_DMA_ENABLE 0x45u
#define C80_DMA_BUSY 0x0au
#define C80_GDMA_ROUTE_MASK 0x7777u

struct c80_desc { unsigned int word[4]; };

static inline unsigned int c80_tx_length(unsigned int size)
{
    if (!size || size > C80_BUFFER_SIZE) return 0;
    return size < 60 ? 60 : size;
}

static inline unsigned int c80_tx_control(unsigned int size)
{
    return (size << 16) | C80_LAST;
}

static inline unsigned int c80_rx_length(unsigned int status)
{
    unsigned int size = (status >> 16) & 0x3fff;
    if (!(status & C80_DDONE) || size < 14 || size > C80_BUFFER_SIZE) return 0;
    return size;
}

static inline int c80_inherited_state_ok(unsigned int route, unsigned int mcr,
                                         unsigned int pcs, unsigned int mode,
                                         unsigned int power, unsigned int ana,
                                         unsigned int pdma)
{
    return (route & 0x200) && mcr == 0x2105e30b && !(pcs & (1u << 12)) &&
           mode == 0x31120019 && !(power & (1u << 4)) &&
           (ana & 0x0c) == 0x04 && pdma == 0x00001410;
}

static inline unsigned int c80_next(unsigned int index, unsigned int count)
{
    return index + 1 == count ? 0 : index + 1;
}

#endif
