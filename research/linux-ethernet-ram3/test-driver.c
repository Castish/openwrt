/* SPDX-License-Identifier: MIT
 * Includes the actual driver with only kernel includes replaced by the API model.
 */
#include "driver-test-shim.h"
#include "driver-under-test.inc"
#include "bsp-descriptors.h"

static unsigned checks;
#define CHECK(expression) do { assert(expression); checks++; } while (0)

static void reset_model(void)
{
    CHECK(!dma_live && !skb_live && !netdev_live);
    memset(model_fe, 0, sizeof(model_fe)); memset(model_pcs, 0, sizeof(model_pcs));
    memset(model_ethsys, 0, sizeof(model_ethsys));
    mmio_writes = dma_alloc_calls = dma_free_calls = received_packets = received_length = 0;
    fail_allocation = -1; fail_rx_skb = fail_skb_copy = 0; stuck_dma = false; next_dma = 0x41000000;
    model_put(model_fe, 0xa04, 0x1410); model_put(model_fe, 0x10100, 0x2105e30b);
    model_put(model_fe, 0x10108, 0xb); model_put(model_fe, 0x508, 0x00000001);
    model_put(model_fe, 0x50c, 0x0200); model_put(model_fe, 0x500, 0x1234ffff);
    model_put(model_pcs, 0, 0x00040140); model_put(model_pcs, 4, 0x4d544950);
    model_put(model_pcs, 0x14, 0x00010000); model_put(model_pcs, 0x20, 0x31120019);
    model_put(model_pcs, 0x128, 0x00014817); model_put(model_ethsys, 0x14, 0x00110214);
}

static struct c80_ram_eth *probe_model(struct platform_device *pdev)
{
    memset(pdev, 0, sizeof(*pdev)); CHECK(c80_probe(pdev) == 0);
    struct c80_ram_eth *p = pdev->dev.data;
    CHECK(p && p->ndev->registered && !p->running && !mmio_writes && !dma_live);
    CHECK(!memcmp(p->ndev->address, (unsigned char[]){2,0,0,0,0,1}, 6));
    return p;
}

static void destroy_model(struct c80_ram_eth *p)
{
    CHECK(!p->running && !dma_live); unregister_netdev(p->ndev); free_netdev(p->ndev);
}

static struct sk_buff *outgoing(unsigned size)
{
    struct sk_buff *skb = make_skb(size); skb->len = size;
    for (unsigned i = 0; i < size; i++) skb->data[i] = i ^ 0x5a;
    return skb;
}

static void rx_frame(struct c80_ram_eth *p, unsigned index, unsigned length, unsigned source)
{
    unsigned char *buffer = p->block[RX_BUFFER].cpu + index * C80_BUFFER_SIZE;
    for (unsigned i = 0; i < C80_BUFFER_SIZE; i++) buffer[i] = i ^ 0xa5;
    buffer[12] = 8; buffer[13] = 6;
    p->rxd[index].word[3] = source << 19;
    p->rxd[index].word[1] = C80_DDONE | C80_LAST | length << 16;
}

int main(void)
{
    /* Independent oracle: bitfield structures taken from the reviewed GPL BSP. */
    CHECK(sizeof(struct PDMA_txdesc) == 16 && sizeof(struct PDMA_rxdesc) == 16);
    for (unsigned size = 1; size <= 2048; size++) {
        struct PDMA_txdesc tx = {0}; unsigned words[4];
        unsigned padded = size < 60 ? 60 : size;
        tx.txd_info2.SDL0 = padded; tx.txd_info2.LS0_bit = 1; tx.txd_info4.FPORT = 1;
        memcpy(words, &tx, 16);
        CHECK(c80_tx_length(size) == padded && words[1] == c80_tx_control(padded));
        CHECK(words[3] == C80_TX_PORT1 && !(words[1] & C80_DDONE));
    }
    for (unsigned size = 0; size < 4096; size++) {
        struct PDMA_rxdesc rx = {0}; unsigned words[4];
        rx.rxd_info2.PLEN0 = size; rx.rxd_info2.DDONE_bit = 1; memcpy(words, &rx, 16);
        CHECK(c80_rx_length(words[1]) == (size >= 14 && size <= 2048 ? size : 0));
        CHECK(c80_rx_length(words[1] & ~C80_DDONE) == 0);
    }
    CHECK(!c80_tx_length(0) && !c80_tx_length(2049));
    for (unsigned size = 64; size <= 128; size += 64)
        for (unsigned i = 0; i < size; i++) CHECK(c80_next(i, size) == (i + 1) % size);

    struct platform_device pdev;
    struct c80_ram_eth *p;
    /* A failed state guard performs no MMIO writes or DMA allocations. */
    for (unsigned which = 0; which < 8; which++) {
        reset_model();
        switch (which) {
        case 0: model_put(model_fe, 0xa04, 0x1455); break;
        case 1: model_put(model_fe, 0x10100, 0); break;
        case 2: model_put(model_pcs, 0, 0x1140); break;
        case 3: model_put(model_pcs, 0x20, 0); break;
        case 4: model_put(model_pcs, 0xe8, 0x10); break;
        case 5: model_put(model_pcs, 0x128, 0); break;
        case 6: model_put(model_pcs, 4, 0); break;
        case 7: model_put(model_ethsys, 0x14, 0); break;
        }
        memset(&pdev, 0, sizeof(pdev)); CHECK(c80_probe(&pdev) == -EINVAL);
        CHECK(!mmio_writes && !dma_alloc_calls && !netdev_live && !pdev.dev.data);
    }
    /* Allocation failures never install rings and release every partial block. */
    for (int failure = 0; failure < 4; failure++) {
        reset_model(); p = probe_model(&pdev); fail_allocation = failure;
        CHECK(c80_open(p->ndev) == -ENOMEM);
        CHECK(!dma_live && dma_free_calls == (unsigned)failure && !mmio_writes);
        destroy_model(p);
    }
    reset_model(); p = probe_model(&pdev); CHECK(c80_open(p->ndev) == 0);
    CHECK(dma_live == 4 && p->running && p->timer.armed && p->ndev->carrier);
    CHECK(model_get(model_fe, 0xa04) == 0x1455 && model_get(model_fe, 0xa28) == 0);
    CHECK(model_get(model_fe, 0x500) == (0x1234ffff & ~0x7777));
    CHECK(model_get(model_fe, 0x800) == p->block[TX_DESC].dma);
    CHECK(model_get(model_fe, 0x900) == p->block[RX_DESC].dma);
    for (unsigned i = 0; i < 63; i++) CHECK(c80_xmit(outgoing(42), p->ndev) == NETDEV_TX_OK);
    CHECK(p->tx_pending == 63 && p->ndev->queue_stopped);
    struct sk_buff *held = outgoing(42); CHECK(c80_xmit(held, p->ndev) == NETDEV_TX_BUSY);
    CHECK(skb_live == 1 && held->len == 42); dev_kfree_skb_any(held);
    unsigned char *tx = p->block[TX_BUFFER].cpu;
    for (unsigned i = 0; i < 60; i++) CHECK(tx[i] == (i < 42 ? (unsigned char)(i ^ 0x5a) : 0));
    for (unsigned i = 0; i < 10; i++) p->txd[i].word[1] |= C80_DDONE;
    c80_poll(&p->timer);
    CHECK(p->tx_pending == 53 && p->tx_tail == 10 && !p->ndev->queue_stopped);
    for (unsigned i = 0; i < 10; i++) CHECK(c80_xmit(outgoing(60), p->ndev) == NETDEV_TX_OK);
    CHECK(p->tx_head == 9 && p->tx_pending == 63);
    for (unsigned i = 0; i < 64; i++) p->txd[i].word[1] |= C80_DDONE;
    c80_poll(&p->timer); CHECK(!p->tx_pending && p->ndev->stats.tx_packets == 73);
    CHECK(c80_xmit(outgoing(2049), p->ndev) == NETDEV_TX_OK && p->ndev->stats.tx_dropped == 1);
    fail_skb_copy = 1; CHECK(c80_xmit(outgoing(42), p->ndev) == NETDEV_TX_OK);
    CHECK(!p->tx_pending && p->ndev->stats.tx_dropped == 2 && !skb_live);
    rx_frame(p, 0, 42, 1); c80_poll(&p->timer);
    CHECK(received_packets == 1 && received_length == 28 && p->ndev->stats.rx_bytes == 42);
    for (unsigned i = 0; i < 28; i++) CHECK(received_data[i] == (unsigned char)((i + 14) ^ 0xa5));
    CHECK(p->rx_next == 1 && p->rxd[0].word[1] == 2048u << 16 && model_get(model_fe, 0x908) == 0);
    rx_frame(p, 1, 2049, 1); rx_frame(p, 2, 13, 1); rx_frame(p, 3, 42, 6); c80_poll(&p->timer);
    CHECK(received_packets == 1 && p->ndev->stats.rx_dropped == 3);
    fail_rx_skb = 1; rx_frame(p, 4, 42, 1); c80_poll(&p->timer);
    CHECK(p->ndev->stats.rx_dropped == 4 && p->rx_next == 5);
    for (unsigned i = 5; i < 38; i++) rx_frame(p, i, 42, 1);
    c80_poll(&p->timer); CHECK(received_packets == 33 && p->rx_next == 37);
    c80_poll(&p->timer); CHECK(received_packets == 34 && p->rx_next == 38);
    char state[4096]; CHECK(ram_state_show(&pdev.dev, NULL, state) > 0);
    CHECK(strstr(state, "pdma=00001455") && strstr(state, "irq_mask=00000000"));
    CHECK(c80_stop(p->ndev) == 0 && !p->running && !p->timer.armed && !dma_live);
    CHECK(model_get(model_fe, 0x500) == 0x1234ffff && model_get(model_fe, 0xa04) == 0x1410);
    CHECK(c80_open(p->ndev) == 0); stuck_dma = true;
    unsigned before = dma_free_calls;
    CHECK(c80_stop(p->ndev) == -EBUSY && dma_live == 4 && dma_free_calls == before);
    CHECK(!p->timer.armed && !p->running && p->block[0].cpu);
    CHECK(c80_open(p->ndev) == -EBUSY && dma_live == 4 && dma_free_calls == before);
    stuck_dma = false; CHECK(c80_open(p->ndev) == 0);
    CHECK(dma_live == 4 && dma_free_calls == before + 4);
    CHECK(c80_stop(p->ndev) == 0); destroy_model(p);
    CHECK(!dma_live && !skb_live && !netdev_live);
    printf("PASS: %u checks; actual driver with model Linux APIs/MMIO; BSP descriptor oracle\n", checks);
    return 0;
}
