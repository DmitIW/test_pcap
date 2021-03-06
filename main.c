#include <stdint.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_hash.h>

#include "filter.h"
//
//  DPDK skeleton
//

#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

#define NUM_MBUFS 128
#define MBUF_CACHE_SIZE 0
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count())
        return -1;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_main(void)
{

    const uint16_t nb_ports = rte_eth_dev_count();
    uint16_t port;

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    for (port = 0; port < nb_ports; port++)
        if (rte_eth_dev_socket_id(port) > 0 &&
                rte_eth_dev_socket_id(port) !=
                        (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
            rte_lcore_id());

    /* Run until the application is quit or killed. */
    /*
     * Receive packets on a port and forward them on the paired
     * port.
     */
    printf("NB_ports: %u\n", nb_ports);
    uint16_t nb_rx;
    uint16_t port_accepted = 0;
    uint16_t port_dropped = 1;
    do {
        /* Get burst of RX packets, from first port of pair. */
        struct rte_mbuf *bufs[BURST_SIZE];
        nb_rx = rte_eth_rx_burst(port_accepted, 0,
                bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            break;

        uint16_t accepted = 0;
        struct rte_mbuf* accepted_bufs[BURST_SIZE];
        uint16_t dropped = 0;
        struct rte_mbuf* dropped_buffs[BURST_SIZE];

        for (uint16_t ind = 0; ind < nb_rx; ind++) {
            struct rte_mbuf* m = bufs[ind];
            if (accept_tcp(m))
                accepted_bufs[accepted++] = m;
            else
                dropped_buffs[dropped++] = m;
        }

        /* Send burst of TX packets, to second port of pair. */
        const uint16_t nb_tx_accepted = rte_eth_tx_burst(port_accepted, 0, accepted_bufs, accepted);
        const uint16_t nb_tx_dropped = rte_eth_tx_burst(port_dropped, 0, dropped_buffs, dropped);

        /* Free any unsent packets. */
        if (unlikely(nb_tx_accepted < accepted)) {
            uint16_t buf;
            printf("WARNING, not transmitted packets (accepted): %d of %d\n",
                   nb_tx_accepted - accepted,
                   accepted);
            for (buf = nb_tx_accepted; buf < accepted; buf++)
                rte_pktmbuf_free(accepted_bufs[buf]);
        }
        if (unlikely(nb_tx_dropped < dropped)) {
            uint16_t buf;
            printf("WARNING, not transmitted packets (dropped): %d of %d\n",
                   nb_tx_dropped - dropped,
                   dropped);
            for (buf = nb_tx_dropped; buf < dropped; buf++)
                rte_pktmbuf_free(dropped_buffs[buf]);
        }
    } while (nb_rx);
    rte_eth_dev_stop(port_dropped);
    rte_eth_dev_stop(port_accepted);
    print_stats();
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    struct filter_settings settings = {
        .flow_number = 65434
    };
    init_filter(&settings);

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "Error: ports not found\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    for (portid = 0; portid < nb_ports; portid++)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                    portid);

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the master core only. */
    lcore_main();

    return 0;
}
