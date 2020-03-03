#ifndef TEST_PCAP_FILTER_H
#define TEST_PCAP_FILTER_H

#include <stdint.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_ip.h>

#include <stddef.h>
#include <rte_compat.h>
#include <rte_hash.h>

struct filter_settings {
    uint64_t flow_number;
};

uint8_t accept_tcp(struct rte_mbuf* m);
void init_filter(struct filter_settings* settings);
void print_stats();

#endif //TEST_PCAP_FILTER_H
