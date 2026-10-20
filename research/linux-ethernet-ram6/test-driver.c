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
    CHECK(!dma_live && !skb_live && !netdev_live && !model_handler);
    CHECK(!napi_added && !napi_live && !model_cpu_blocked && !model_in_irq && !model_in_poll);
    memset(model_fe, 0, sizeof(model_fe)); memset(model_pcs, 0, sizeof(model_pcs));
    memset(model_ethsys, 0, sizeof(model_ethsys));
    mmio_writes = dma_alloc_calls = dma_free_calls = received_packets = received_length = 0;
    fail_allocation = -1; fail_rx_skb = fail_skb_copy = 0; stuck_dma = false; next_dma = 0x41000000;
    ignore_done_ack = false; model_irq_number = 19;
    fail_request_irq = fail_register = fail_sysfs = idle_pending = idle_error = 0;
    irq_depth = irq_enable_calls = irq_disable_calls = irq_sync_calls = idle_checks = 0;
    napi_schedules = napi_completions = dma_setup_writes = dma_start_writes = ack_writes = 0;
    complete_allowed = true; complete_hook = NULL;
    fail_mdio_init = 0; mdio_init_calls = mdio_snapshot_calls = 0;
    mdio_ready = true; mdio_link_calls = mdio_link_state_calls = 0;
    CHECK(!model_rtnl);
    model_put(model_fe, 0xa04, 0x1410); model_put(model_fe, 0x10100, 0x2105e30b);
    model_put(model_fe, 0xa20, 0x10001);
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
    CHECK(model_handler == c80_irq && irq_depth == 1 && !irq_enable_calls);
    CHECK(napi_added == 1 && !napi_live && !p->napi.enabled && !p->napi.scheduled);
    CHECK(!memcmp(p->ndev->address, (unsigned char[]){2,0,0,0,0,1}, 6));
    CHECK(p->mdio == &model_mdio_bus && mdio_init_calls == 1);
    return p;
}

static void destroy_model(struct c80_ram_eth *p)
{
    CHECK(!p->running && !dma_live && !napi_live && irq_depth == 1);
    unregister_netdev(p->ndev); free_irq(p->irq, p); netif_napi_del(&p->napi); free_netdev(p->ndev);
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
    model_put(model_fe, DMA_IRQ_STATUS, model_get(model_fe, DMA_IRQ_STATUS) | 0x10000);
}

static void fire_irq(struct c80_ram_eth *p, bool force)
{
    CHECK(!irq_depth && model_handler && !model_cpu_blocked && !model_in_poll);
    if (!force) CHECK(model_get(model_fe, DMA_IRQ_STATUS) & model_get(model_fe, DMA_IRQ_MASK));
    model_cpu_blocked = model_in_irq = true;
    CHECK(model_handler(p->irq, model_irq_data) == IRQ_HANDLED);
    model_in_irq = model_cpu_blocked = false;
    CHECK(!model_get(model_fe, DMA_IRQ_MASK));
}

static int poll_napi(struct c80_ram_eth *p, unsigned budget)
{
    CHECK(!model_in_irq && !model_cpu_blocked && p->napi.enabled && p->napi.scheduled);
    model_in_poll = true; int work = p->napi.poll(&p->napi, budget); model_in_poll = false;
    CHECK(!model_cpu_blocked && work >= 0 && (unsigned)work <= budget);
    return work;
}

static int interrupt_poll(struct c80_ram_eth *p)
{
    fire_irq(p, false); CHECK(p->napi.scheduled); return poll_napi(p, 64);
}

static void tx_done(struct c80_ram_eth *p, unsigned count)
{
    unsigned index = p->tx_tail;
    CHECK(count <= p->tx_pending);
    for (unsigned i = 0; i < count; i++) {
        p->txd[index].word[1] |= C80_DDONE; index = c80_next(index, C80_TX_COUNT);
    }
    model_put(model_fe, DMA_IRQ_STATUS, model_get(model_fe, DMA_IRQ_STATUS) | 1);
}

static struct c80_ram_eth *late_rx_p;
static void late_rx(void) { rx_frame(late_rx_p, late_rx_p->rx_next, 100, 1); }

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
    /* Wrong inherited grouping must reject the measured ID255 route. */
    for (unsigned which = 0; which < 12; which++) {
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
        case 8: model_put(model_fe, 0x20, 0x21021000); break;
        case 9: model_put(model_fe, 0xa50, 1); break;
        case 10: model_put(model_fe, 0xa54, 0x10000); break;
        case 11: model_put(model_fe, 0xa28, 1); break;
        }
        memset(&pdev, 0, sizeof(pdev)); CHECK(c80_probe(&pdev) == -EINVAL);
        CHECK(!mmio_writes && !dma_alloc_calls && !netdev_live && !pdev.dev.data);
        CHECK(!model_handler && !napi_added);
    }
    /* CPU-link action must serialize against ndo_open/stop and reject every
     * active/unsafe state before calling the separately tested MDIO helper. */
    reset_model(); p = probe_model(&pdev);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test", 4) == -EINVAL);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "oops\n", 5) == -EINVAL);
    CHECK(!mdio_link_calls && !model_rtnl && !mmio_writes);
    p->ndev->admin_up = true;
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EBUSY); p->ndev->admin_up = false;
    p->running = true;
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EBUSY); p->running = false;
    p->block[0].cpu = (void *)1;
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EBUSY); p->block[0].cpu = NULL;
    p->irq_enabled = true;
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EBUSY); p->irq_enabled = false;
    model_put(model_fe, DMA_CFG, 0x1455);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EINVAL); model_put(model_fe, DMA_CFG, 0x1410);
    model_put(model_fe, DMA_IRQ_MASK, 1);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EINVAL); model_put(model_fe, DMA_IRQ_MASK, 0);
    CHECK(!mdio_link_calls && !model_rtnl && !mmio_writes);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == 5);
    CHECK(mdio_link_calls == 1 && !model_rtnl && !mmio_writes);
    char link_state[4096];
    CHECK(cpu_link_test_show(&pdev.dev, NULL, link_state) > 0 && strstr(link_state,"CPU-link helper delegate"));
    CHECK(mdio_link_state_calls == 1);
    mdio_ready = false;
    CHECK(c80_open(p->ndev) == -EUCLEAN && !mmio_writes && !dma_live);
    mdio_ready = true; CHECK(c80_open(p->ndev) == 0);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == -EBUSY && mdio_link_calls == 1);
    CHECK(c80_stop(p->ndev) == 0);
    CHECK(cpu_link_test_store(&pdev.dev, NULL, "test\n", 5) == 5 && mdio_link_calls == 2);
    destroy_model(p);
    /* Platform/IRQ/netdev/sysfs failure unwind must leave no live handler. */
    for (unsigned failure = 0; failure < 5; failure++) {
        reset_model();
        switch (failure) {
        case 0: model_irq_number = -ENXIO; break;
        case 1: fail_request_irq = -EBUSY; break;
        case 2: fail_register = -ENOMEM; break;
        case 3: fail_sysfs = -ENOMEM; break;
        case 4: fail_mdio_init = -ENOMEM; break;
        }
        memset(&pdev, 0, sizeof(pdev)); CHECK(c80_probe(&pdev) < 0);
        CHECK(!mmio_writes && !dma_alloc_calls && !netdev_live && !pdev.dev.data);
        CHECK(!model_handler && !napi_added && !napi_live);
    }
    /* Reject uncleared done bits, wrong polarity, unsupported pending query.
     * These paths must stop before any DMA address/enable write or allocation. */
    for (unsigned failure = 0; failure < 3; failure++) {
        reset_model(); p = probe_model(&pdev);
        switch (failure) {
        case 0: ignore_done_ack = true; break;
        case 1: idle_pending = 1; break;
        case 2: idle_error = -EOPNOTSUPP; break;
        }
        CHECK(c80_open(p->ndev) == -EIO);
        CHECK(!dma_live && !dma_alloc_calls && !dma_setup_writes && !dma_start_writes);
        CHECK(!p->running && irq_depth == 1 && !napi_live && !model_cpu_blocked);
        CHECK(!model_get(model_fe, DMA_IRQ_MASK));
        CHECK(idle_checks == (failure != 0));
        if (failure) CHECK(p->pending_check == (failure == 1 ? 1 : -EOPNOTSUPP));
        destroy_model(p);
    }
    /* Allocation failures release partial blocks, with no DMA installation. */
    for (int failure = 0; failure < 4; failure++) {
        reset_model(); p = probe_model(&pdev); fail_allocation = failure;
        CHECK(c80_open(p->ndev) == -ENOMEM);
        CHECK(!dma_live && dma_free_calls == (unsigned)failure);
        CHECK(!dma_setup_writes && !dma_start_writes && irq_depth == 1 && !napi_live);
        CHECK(!model_get(model_fe, DMA_IRQ_MASK) && idle_checks == 1);
        destroy_model(p);
    }
    reset_model(); p = probe_model(&pdev); CHECK(c80_open(p->ndev) == 0);
    CHECK(dma_live == 4 && p->running && p->napi.enabled && p->ndev->carrier);
    CHECK(!irq_depth && p->irq_enabled && !p->napi.scheduled && !p->irq_fault);
    CHECK(model_get(model_fe, DMA_CFG) == 0x1455 && model_get(model_fe, DMA_IRQ_MASK) == DMA_IRQ_DONE);
    CHECK(!model_get(model_fe, DMA_IRQ_STATUS) && p->pending_check == 0);
    CHECK(model_get(model_fe, GDM_FWD) == (0x1234ffff & ~0x7777));
    CHECK(model_get(model_fe, TX_BASE) == p->block[TX_DESC].dma);
    CHECK(model_get(model_fe, RX_BASE) == p->block[RX_DESC].dma);
    for (unsigned i = 0; i < 63; i++) CHECK(c80_xmit(outgoing(42), p->ndev) == NETDEV_TX_OK);
    CHECK(p->tx_pending == 63 && p->ndev->queue_stopped);
    struct sk_buff *held = outgoing(42); CHECK(c80_xmit(held, p->ndev) == NETDEV_TX_BUSY);
    CHECK(skb_live == 1 && held->len == 42); dev_kfree_skb_any(held);
    unsigned char *tx = p->block[TX_BUFFER].cpu;
    for (unsigned i = 0; i < 60; i++) CHECK(tx[i] == (i < 42 ? (unsigned char)(i ^ 0x5a) : 0));
    tx_done(p, 10); CHECK(interrupt_poll(p) == 0);
    CHECK(p->tx_pending == 53 && p->tx_tail == 10 && !p->ndev->queue_stopped);
    CHECK(!p->napi.scheduled && p->irq_count == 1 && p->irq_tx == 1 && !p->irq_rx);
    for (unsigned i = 0; i < 10; i++) CHECK(c80_xmit(outgoing(60), p->ndev) == NETDEV_TX_OK);
    CHECK(p->tx_head == 9 && p->tx_pending == 63);
    tx_done(p, 63); CHECK(interrupt_poll(p) == 0);
    CHECK(!p->tx_pending && p->ndev->stats.tx_packets == 73);
    CHECK(c80_xmit(outgoing(2049), p->ndev) == NETDEV_TX_OK && p->ndev->stats.tx_dropped == 1);
    fail_skb_copy = 1; CHECK(c80_xmit(outgoing(42), p->ndev) == NETDEV_TX_OK);
    CHECK(!p->tx_pending && p->ndev->stats.tx_dropped == 2 && !skb_live);
    rx_frame(p, 0, 42, 1); CHECK(interrupt_poll(p) == 1);
    CHECK(received_packets == 1 && received_length == 28 && p->ndev->stats.rx_bytes == 42);
    for (unsigned i = 0; i < 28; i++) CHECK(received_data[i] == (unsigned char)((i + 14) ^ 0xa5));
    CHECK(p->rx_next == 1 && p->rxd[0].word[1] == 2048u << 16 && model_get(model_fe, RX_CPU) == 0);
    rx_frame(p, 1, 2049, 1); rx_frame(p, 2, 13, 1); rx_frame(p, 3, 42, 6);
    CHECK(interrupt_poll(p) == 3);
    CHECK(received_packets == 1 && p->ndev->stats.rx_dropped == 3);
    fail_rx_skb = 1; rx_frame(p, 4, 42, 1); CHECK(interrupt_poll(p) == 1);
    CHECK(p->ndev->stats.rx_dropped == 4 && p->rx_next == 5);

    /* Exhausted budget keeps interrupts masked and NAPI scheduled. */
    for (unsigned i = 5; i < 70; i++) rx_frame(p, i, 42, 1);
    CHECK(interrupt_poll(p) == 64);
    CHECK(received_packets == 65 && p->rx_next == 69 && p->napi.scheduled);
    CHECK(!model_get(model_fe, DMA_IRQ_MASK));
    CHECK(poll_napi(p, 64) == 1);
    CHECK(received_packets == 66 && p->rx_next == 70 && !p->napi.scheduled);
    CHECK(model_get(model_fe, DMA_IRQ_MASK) == DMA_IRQ_DONE);

    /* A budget-zero NAPI call reclaims TX, without touching RX or status. */
    CHECK(c80_xmit(outgoing(64), p->ndev) == NETDEV_TX_OK); tx_done(p, 1);
    rx_frame(p, p->rx_next, 100, 1); fire_irq(p, false);
    unsigned acks = ack_writes, completions = napi_completions, received = received_packets;
    CHECK(poll_napi(p, 0) == 0);
    CHECK(!p->tx_pending && received_packets == received && p->rx_next == 70);
    CHECK(ack_writes == acks && napi_completions == completions && p->napi.scheduled);
    CHECK(model_get(model_fe, DMA_IRQ_STATUS) == DMA_IRQ_DONE && !model_get(model_fe, DMA_IRQ_MASK));
    CHECK(poll_napi(p, 64) == 1 && !p->napi.scheduled);

    /* Preserve unrelated W1C status; busy-poll ownership prevents IRQ rearm. */
    rx_frame(p, p->rx_next, 100, 1);
    model_put(model_fe, DMA_IRQ_STATUS, model_get(model_fe, DMA_IRQ_STATUS) | 0x40000000);
    complete_allowed = false; CHECK(interrupt_poll(p) == 1);
    CHECK(p->napi.scheduled && !model_get(model_fe, DMA_IRQ_MASK));
    CHECK(model_get(model_fe, DMA_IRQ_STATUS) == 0x40000000);
    complete_allowed = true; CHECK(poll_napi(p, 64) == 0);
    CHECK(!p->napi.scheduled && model_get(model_fe, DMA_IRQ_MASK) == DMA_IRQ_DONE);
    model_put(model_fe, DMA_IRQ_STATUS, 0);

    /* Completion between the last empty-ring check and rearm must retrigger. */
    rx_frame(p, p->rx_next, 100, 1); late_rx_p = p; complete_hook = late_rx;
    received = received_packets; CHECK(interrupt_poll(p) == 1);
    CHECK(received_packets == received + 1 && !complete_hook);
    CHECK(model_get(model_fe, DMA_IRQ_STATUS) == 0x10000);
    CHECK(model_get(model_fe, DMA_IRQ_MASK) == DMA_IRQ_DONE);
    CHECK(interrupt_poll(p) == 1 && received_packets == received + 2);

    /* Exercise multiple RX ring wraps with minimum and maximum accepted frames. */
    for (unsigned i = 0; i < 260; i++) {
        unsigned index = p->rx_next, size = i & 1 ? 14 : 2048;
        rx_frame(p, index, size, 1); CHECK(interrupt_poll(p) == 1);
        CHECK(p->rxd[index].word[1] == 2048u << 16 && !p->rxd[index].word[3]);
    }
    char state[4096]; CHECK(ram_state_show(&pdev.dev, NULL, state) > 0);
    CHECK(strstr(state, "pdma=00001455") && strstr(state, "irq_mask=00010001"));
    CHECK(strstr(state, "irq=19 irq_enabled=1") && strstr(state, "irq_fault=0 faults=0 idle_pending=0"));
    CHECK(switch_state_show(&pdev.dev, NULL, state) > 0 && strstr(state, "MDIO helper delegate"));
    CHECK(mdio_snapshot_calls == 1 && p->running && p->irq_enabled);
    CHECK(p->irq_count > 260 && p->irq_rx > 260 && p->napi_polls > p->irq_count);
    CHECK(c80_stop(p->ndev) == 0 && !p->running && !p->napi.enabled && !dma_live);
    CHECK(irq_depth == 1 && !p->irq_enabled && irq_sync_calls == 1);
    CHECK(model_get(model_fe, GDM_FWD) == 0x1234ffff && model_get(model_fe, DMA_CFG) == 0x1410);
    CHECK(c80_open(p->ndev) == 0); stuck_dma = true;
    unsigned before = dma_free_calls;
    CHECK(c80_stop(p->ndev) == -EBUSY && dma_live == 4 && dma_free_calls == before);
    CHECK(!p->napi.enabled && !p->running && p->block[0].cpu && irq_depth == 1);
    CHECK(c80_open(p->ndev) == -EBUSY && dma_live == 4 && dma_free_calls == before);
    stuck_dma = false; CHECK(c80_open(p->ndev) == 0);
    CHECK(dma_live == 4 && dma_free_calls == before + 4 && !irq_depth);
    CHECK(c80_stop(p->ndev) == 0); destroy_model(p);

    /* An IRQ with no owned event disables its GIC line; DMA buffers stay pinned
     * until normal netdown synchronizes IRQ/NAPI and quiets the engine. */
    reset_model(); p = probe_model(&pdev); CHECK(c80_open(p->ndev) == 0);
    rx_frame(p, 0, 100, 1); fire_irq(p, false);
    CHECK(p->napi.scheduled);
    model_put(model_fe, DMA_IRQ_STATUS, 0);
    fire_irq(p, true);
    CHECK(p->irq_fault && p->irq_faults == 1 && irq_depth == 1 && !p->irq_enabled);
    CHECK(p->ndev->queue_stopped && dma_live == 4 && p->running);
    CHECK(poll_napi(p, 64) == 0 && !p->napi.scheduled);
    CHECK(!model_get(model_fe, DMA_IRQ_MASK) && !received_packets);
    unsigned disabled = irq_disable_calls;
    CHECK(c80_stop(p->ndev) == 0 && !dma_live && irq_depth == 1);
    CHECK(irq_disable_calls == disabled);
    CHECK(c80_open(p->ndev) == 0 && !p->irq_fault && !irq_depth);
    /* Stop while NAPI is scheduled must prevent any later descriptor access. */
    rx_frame(p, 0, 100, 1); fire_irq(p, false);
    CHECK(p->napi.scheduled && c80_stop(p->ndev) == 0);
    CHECK(!p->napi.scheduled && !napi_live && irq_depth == 1 && !dma_live);
    destroy_model(p);
    CHECK(!dma_live && !skb_live && !netdev_live && !model_handler && !napi_added);
    printf("PASS: %u checks; actual driver with model Linux APIs/MMIO; BSP descriptor oracle\n", checks);
    return 0;
}
