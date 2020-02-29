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

//
//  DPDK skeleton
//

#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

#define NUM_MBUFS 128
#define MBUF_CACHE_SIZE 0
#define BURST_SIZE 32

struct tcp_flow_key {
        uint32_t first_ip;
        uint16_t first_port;
        uint32_t second_ip;
        uint16_t second_port;
};
static struct rte_hash* g_flows;
enum HandshakePhase {
    Qestion = 0x01u,
    Answer = 0x02u,
    Accept = 0x03u
};
struct tcp_flow_state {
    enum HandshakePhase state;
    uint8_t direction; // src ip < dst ip
    uint32_t seq;
    uint32_t ack;
};
struct rte_mempool* g_tcp_flow_state_pool = NULL;
static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

static uint8_t analyze_hdr(struct tcp_hdr* tcp_header, struct tcp_flow_key* key, uint8_t direction) {

    struct tcp_flow_state* flow_state;
    int in_table = rte_hash_lookup_data(g_flows, key, (void**)&flow_state);
    uint8_t syn = tcp_header->tcp_flags & 0x02u;
    uint8_t brk = tcp_header->tcp_flags & 0x01u + tcp_header->tcp_flags & 0x04u;
    uint32_t seq = htonl(tcp_header->sent_seq);
    uint32_t ack = htonl(tcp_header->recv_ack);

    if (in_table < 0) {
        rte_mempool_get(g_tcp_flow_state_pool, (void**)&flow_state);
        if (syn == 0)
            return 0;
        else {
            flow_state->direction = direction;
            flow_state->seq = tcp_header->sent_seq;
            flow_state->ack = tcp_header->recv_ack;
            flow_state->state = Qestion;
            if (rte_hash_add_key_data(g_flows, key, flow_state) != 0)
                printf("Warning: Trouble with adding state to flows hash table");
            return 1;
        }
    } else {
        return 1;
//        switch (flow_state->state) {
//            case Qestion:
//                if (syn == 0 || direction == flow_state->direction || flow_state->seq + 1 != tcp_header->recv_ack)
//                    return 0;
//                flow_state->state = Answer;
//                flow_state->direction = direction;
//                flow_state->seq = tcp_header->sent_seq;
//                flow_state->ack = tcp_header->recv_ack;
//                return 1;
//            case Answer:
//                if (syn == 1 || direction == flow_state->direction || flow_state->seq + 1 != tcp_header->recv_ack
//                             || flow_state->ack != tcp_header->sent_seq)
//                    return 0;
//                flow_state->state = Accept;
//                return 1;
//            case Accept:
//                if (brk != 0) {
//                    rte_hash_del_key(g_flows, key);
//                    rte_mempool_put(g_tcp_flow_state_pool, flow_state);
//                }
//                return 1;
//            default:
//                printf("Warning: Unconditional header state");
//                break;
//        }
    }
}

static inline uint8_t accept_tcp(struct rte_mbuf* m) {

    struct ether_hdr* eth_header = rte_pktmbuf_mtod(m, struct ether_hdr*);

    struct ipv4_hdr* ip_header = (struct ipv4_hdr*)((char*)eth_header + sizeof(struct ether_hdr));
    uint32_t src_addr = ip_header->src_addr;
    uint32_t dst_addr = ip_header->dst_addr;

    struct tcp_hdr* tcp_header = (struct tcp_hdr*)((char*)ip_header + sizeof(struct ipv4_hdr));
    uint16_t src_port = tcp_header->src_port;
    uint16_t dst_port = tcp_header->dst_port;

    uint8_t direction = src_addr < dst_addr;

    struct tcp_flow_key key;
    if (direction) {
        key.first_ip = src_addr;
        key.first_port = src_port;

        key.second_ip = dst_addr;
        key.second_port = dst_port;

    } else {
        key.first_ip = dst_addr;
        key.first_port = dst_port;

        key.second_ip = src_addr;
        key.second_port = src_addr;
    }

    return analyze_hdr(tcp_header, &key, direction);
}
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
    uint32_t common_accepted = 0;
    for (port = 0; port < nb_ports; port++) {

        uint16_t nb_rx;

        do {
            /* Get burst of RX packets, from first port of pair. */
            struct rte_mbuf *bufs[BURST_SIZE];
            nb_rx = rte_eth_rx_burst(port, 0,
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
            common_accepted += accepted;
            /* Send burst of TX packets, to second port of pair. */
            const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                    accepted_bufs, accepted);

            for (uint16_t buf = 0; buf < dropped; buf++)
                rte_pktmbuf_free(dropped_buffs[buf]);

            /* Free any unsent packets. */
            if (unlikely(nb_tx < accepted)) {
                uint16_t buf;
                printf("WARNING, not transmitted packets: %d of %d\n",
                       nb_tx - accepted,
                       accepted);
                for (buf = nb_tx; buf < accepted; buf++)
                    rte_pktmbuf_free(bufs[buf]);
            }
        } while (nb_rx);
        rte_eth_dev_stop(port);
    }
    printf("Accepted count: %u\n", common_accepted);
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

    struct rte_hash_parameters hash_params = {
            .entries = 64536,
            .key_len = sizeof(struct tcp_flow_key),
            .socket_id = (int)rte_socket_id(),
            .hash_func_init_val = 0,
            .name = "tcp flows table"
    };
    g_flows = rte_hash_create(&hash_params);
    if (g_flows == NULL)
    {
        rte_exit(EXIT_FAILURE, "No hash table created\n");
    }
    g_tcp_flow_state_pool = rte_mempool_create("tcp_state_pool", 65535, sizeof(struct tcp_flow_state),
                                          0, 0, NULL, NULL,
                                          NULL, NULL, (int)rte_socket_id(), 0);
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
