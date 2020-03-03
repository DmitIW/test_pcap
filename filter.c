#include "filter.h"
#include <math.h>
#include "rte_jhash.h"

#define ___DEBUG

enum HandshakePhase {
    LISTEN = 0x00u,
    SYN_SENT = 0x01u,
    SYN_SENT_LOOP = 0x02u,
    PRE_ESTB = 0x03u,
    PRE_ESTB_LOOP = 0x04u,
    ESTABLISHED = 0x05u
};
struct tcp_flow_key {
    // first ip always smaller as number than second, direction of connect stored in value of hash table
    uint32_t fIp;   // first ip address
    uint32_t fPrt;  // first port
    uint32_t sIp;   // second ip address
    uint32_t sPrt;  // second port
};
struct tcp_flow_state {
    enum HandshakePhase state;
    uint16_t first_to_second; // from first ip to second ip in hash key or inverse direction
    uint32_t seq;            // last used seq value
    uint32_t ack;            // last used ack value
};
#define FIN 0x01u
#define SYN 0x02u
#define ACK 0x10u
#define NXT 0x40u
#define ACTIVE_FLAGS_TYPE uint32_t

//
// Mem operations
//

struct rte_mempool* g_tcp_flow_state_pool = NULL;  // mempool for hash table values
static inline void get_mem(struct tcp_flow_state** object) { rte_mempool_get(g_tcp_flow_state_pool, (void**)object);}
static inline void free_mem(struct tcp_flow_state* object) { rte_mempool_put(g_tcp_flow_state_pool, object); }
static void mempool_init(struct filter_settings* settings) {
    // Init mempool for hash table values
    g_tcp_flow_state_pool = rte_mempool_create("tcp_state_pool", settings->flow_number + 1000,
            sizeof(struct tcp_flow_state),0, 0, NULL, NULL,
                    NULL, NULL, (int)rte_socket_id(), 0);
}

//
//  Hash table workflow
//

#ifdef ___DEBUG
static uint64_t hash_table_size = 0;
static uint64_t return_default_value = 0;
static uint64_t add_new_element = 0;
static uint64_t remove_element = 0;
#endif

static uint32_t hash_tcp_key(const void* k, uint32_t length, uint32_t initval) {
    // Compute hash value trough polynomial hash
    struct tcp_flow_key* key = (struct tcp_flow_key*)k;
    uint32_t frs, scn, trd, frt;

    uint32_t l = sizeof(uint32_t);
    frs = rte_jhash_32b(&key->fIp, l, initval);

    uint32_t prime_number = 337;
    scn = rte_jhash_32b(&key->sIp, l, initval) * prime_number;

    prime_number *= prime_number;
    trd = rte_jhash_32b(&key->fPrt, l, initval) * prime_number;

    prime_number *= prime_number;
    frt = rte_jhash_32b(&key->sPrt, l, initval) * prime_number;
    uint32_t v = frs + scn + trd + frt;

    return v;
}
static struct rte_hash* g_flows;                  // hash table
static void hashtable_init(struct filter_settings* settings) {
    struct rte_hash_parameters hash_params = {
            .entries = settings->flow_number,
            .key_len = sizeof(struct tcp_flow_key),
            .socket_id = (int)rte_socket_id(),
            .hash_func_init_val = 0,
            .hash_func = hash_tcp_key,
            .name = "tcp flows table"
    };
    g_flows = rte_hash_create(&hash_params);
    if (g_flows == NULL)
    {
        rte_exit(EXIT_FAILURE, "No hash table created\n");
    }
}

static inline struct tcp_flow_state* at_key_or_default(struct tcp_flow_key* key, struct tcp_flow_state* default_value) {
    // Return value from hash table or return new flow_state value
    struct tcp_flow_state* flow_state;
    if (rte_hash_lookup_data(g_flows, key, (void**)&flow_state) < 0) {
#ifdef ___DEBUG
        return_default_value++;
#endif
        flow_state = default_value;
    }
    return flow_state;
}

static inline uint8_t add_by_key(struct tcp_flow_key* key, struct tcp_flow_state* value) {
    // Try to add new value to hash table. Return 1 if adding was successful, 0 otherwise
    struct tcp_flow_state* tmp;
    if (rte_hash_lookup_data(g_flows, key, (void**)&tmp) < 0) {
#ifdef ___DEBUG
        add_new_element++;
        hash_table_size++;
#endif
        struct tcp_flow_state* new_element;
        get_mem(&new_element);
        new_element->state = value->state;
        new_element->seq = value->seq;
        new_element->first_to_second = value->first_to_second;
        new_element->ack = value->ack;

        rte_hash_add_key_data(g_flows, key, new_element);

        return 1;
    }
    return 0;
}

static inline uint8_t delete_by_key(struct tcp_flow_key* key) {
    // Try to delete value by key from hash table and free mem of value. Return 1 if success, 0 otherwise
    struct tcp_flow_state* flow_state;
    if (rte_hash_lookup_data(g_flows, key, (void**)&flow_state) < 0)
        return 0;
    rte_hash_del_key(g_flows, key);
    free_mem(flow_state);
#ifdef ___DEBUG
    hash_table_size--;
    remove_element--;
#endif
    return 1;
}

static inline void update_values(struct tcp_flow_state* state, struct tcp_hdr* hdr) {
    // Update seq and ack values for stored package
    state->ack = ntohl(hdr->recv_ack);
    state->seq = ntohl(hdr->sent_seq);
}

//
// Algoritm workflow
//

static struct rte_hash* fsm_transitions; // Finite state machine
struct rte_mempool* fsm_states;          // for TCP handshake parsing
struct fsm_transition {
    enum HandshakePhase phase;
    ACTIVE_FLAGS_TYPE active_flags;
    // first 6 bit for tcp flags
    // 7 bit for direction
    // 8 bit for chck flag
};
static inline void add_new_transition(enum HandshakePhase phase_from, ACTIVE_FLAGS_TYPE flags_from, enum HandshakePhase phase_to) {
    // Add new transition to FSM. FROM fstm_transition{phase_from, flags_from} TO phase_to
    struct fsm_transition t = {
            .phase = phase_from,
            .active_flags = flags_from
    };
    enum HandshakePhase* s;
    rte_mempool_get(fsm_states, (void**)&s);
    *s = phase_to;
    rte_hash_add_key_data(fsm_transitions, &t, s);
}
static void init_fsm() {
    struct rte_hash_parameters hash_params = {
            .entries = 400,
            .key_len = sizeof(struct fsm_transition),
            .socket_id = (int)rte_socket_id(),
            .hash_func_init_val = 0,
            .name = "finite state machine for tcp handshake parsing"
    };
    fsm_transitions = rte_hash_create(&hash_params);
    if (fsm_transitions == NULL) { rte_exit(EXIT_FAILURE, "No FSM created\n"); }
    fsm_states = rte_mempool_create("FSM states", 400,
                                    sizeof(enum HandshakePhase),0, 0, NULL, NULL,
                                    NULL, NULL, (int)rte_socket_id(), 0);

    // Logic of handshake parsing

    add_new_transition(LISTEN, SYN, SYN_SENT);

    add_new_transition(SYN_SENT, ACK + NXT, PRE_ESTB);
    add_new_transition(SYN_SENT, SYN, SYN_SENT_LOOP);

    add_new_transition(SYN_SENT_LOOP, ACK + NXT, PRE_ESTB);
    add_new_transition(SYN_SENT_LOOP, SYN, SYN_SENT);

    add_new_transition(PRE_ESTB, ACK + NXT, ESTABLISHED);
    add_new_transition(PRE_ESTB, ACK, PRE_ESTB_LOOP);
//    add_new_transition(PRE_ESTB, SYN, SYN_SENT);

    add_new_transition(PRE_ESTB_LOOP, ACK + NXT, ESTABLISHED);
    add_new_transition(PRE_ESTB_LOOP, ACK, PRE_ESTB);
//    add_new_transition(PRE_ESTB_LOOP, SYN, SYN_SENT);
}
#ifdef ___DEBUG
static uint64_t without_transition = 0;
static uint64_t dropped = 0;
static uint64_t accepted = 0;
static uint64_t established = 0;
static uint64_t lost = 0;
#endif

static inline uint8_t get_next_state(struct fsm_transition* state) {
    // Try to get next state by using FSM transitions. Update get state->phase if next state exists and return 1, otherwise 0
    enum HandshakePhase* next_s;
    if (rte_hash_lookup_data(fsm_transitions, state, (void**)&next_s) < 0) {
#ifdef ___DEBUG
        without_transition++;
        if (state->phase != LISTEN) {
            lost++;
            printf("Phase of lost: %x\nFlags of lost: %x\n\n", state->phase, state->active_flags);
        }
#endif
        return 0;
    }

    state->phase = *next_s;
    return 1;
}

static inline uint32_t nxt_flag(struct tcp_flow_state* flow_state, struct tcp_hdr* tcp_header) {
    // Check header correct. Return NXT if seq from header equal to seq + 1 from flow_state.
    if (flow_state->seq + 1 == ntohl(tcp_header->sent_seq))
        return NXT;
    return 0x00u;
}

static uint8_t analyze_hdr(struct tcp_hdr* tcp_header, struct tcp_flow_key* key, uint8_t direction) {
    // Package analyzer
    struct tcp_flow_state default_value = {
            .state = LISTEN,
            .first_to_second = direction
    };
    update_values(&default_value, tcp_header);
    struct tcp_flow_state* flow_state = at_key_or_default(key, &default_value);

    // accepted if it was
    if (flow_state->state == ESTABLISHED) {
#ifdef ___DEBUG
        accepted++;
        established++;
#endif
        return 1;
    }
    // analyze otherwise
    struct fsm_transition t = {
            .phase = flow_state->state,
            .active_flags = (tcp_header->tcp_flags & SYN) +  // SYN
                            (tcp_header->tcp_flags & ACK) +  // ACK
                            nxt_flag(flow_state, tcp_header) // NXT
    };

    if (!get_next_state(&t)) {
#ifdef ___DEBUG
        if (t.phase == 3 || t.phase == 4)
            printf("Port src: %u\nPort dst: %u\n", ntohs(key->sPrt), ntohs(key->fPrt));
        dropped++;
#endif
        return 0;
    }
    flow_state->state = t.phase;
    if (t.active_flags & SYN + t.active_flags & NXT)
        update_values(flow_state, tcp_header);
    else if (flow_state->state == SYN_SENT)
        add_by_key(key, flow_state);
#ifdef ___DEBUG
    accepted++;
#endif
    return 1;
}

uint8_t accept_tcp(struct rte_mbuf* m) {
    // Parse package and run analyzer for it
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
        key.fIp = src_addr;
        key.fPrt = src_port;

        key.sIp = dst_addr;
        key.sPrt = dst_port;

    } else {
        key.fIp = dst_addr;
        key.fPrt = dst_port;

        key.sIp = src_addr;
        key.sPrt = src_port;
    }
    return analyze_hdr(tcp_header, &key, direction);
}
void print_stats() {
    // Collect all stats for filter. Function for debug
#ifdef ___DEBUG
    printf("Dropped: %lu\n", dropped);
    printf("Without transition: %lu\n", without_transition);
    printf("Accepted: %lu\n", accepted);
    printf("Established: %lu\n", established);
    printf("Lost: %lu\n", lost);
    printf("Hash table size: %lu\n", hash_table_size);
    printf("Hash table; add new element: %lu\n", add_new_element);
    printf("Hash table; return default value: %lu\n", return_default_value);
    printf("Hash table; remove element: %lu\n", remove_element);
#endif
}

static void RunAllTests ();

void init_filter(struct filter_settings* settings) {
    hashtable_init(settings);
    mempool_init(settings);
    init_fsm();
}
