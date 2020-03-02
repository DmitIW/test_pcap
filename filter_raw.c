//#include "filter.h"

#define ___DEBUG                     // Show stats for filter at end
#define ___TEST                      // Run tests. Filter doesn't work in production, accept all packages
#define ___STRICT_FLAGS_EQUAL        // Check all flags in header or only important for handshake
#define ___BIDIRECTIONAL             // Analyze in context of bidirectional connection (clnt -> srvr and srvr -> clnt) or only clnt -> srvr
//
// Support structs
//

enum HandshakePhase {
    LISTEN = 0x00U,
    SYN_SENT_INITIATOR = 0x01u,
    SYN_SENT_RECIPIENT = 0x02u,
    ESTABLISHED = 0x03u,
    SKIP = 0x04u,
    SYN_SENT_RECIPIENT_WOT_ACK = 0x05u,
    SYN_SENT_INITIATOR_LOOP = 0x06u,
    SYN_SENT_RECIPIENT_LOOP = 0x07u
};
struct tcp_flow_key {
    // first ip always smaller as number than second, direction of connect stored in value of hash table
    uint32_t fIp;   // first ip address
    uint16_t fPrt;  // first port
    uint32_t sIp;   // second ip address
    uint16_t sPrt;  // second port
};
struct tcp_flow_state {
    enum HandshakePhase state;
    uint16_t first_to_second; // from first ip to second ip in hash key or inverse direction
    uint32_t seq;            // last used seq value
    uint32_t ack;            // last used ack value
};
#define CLNT 0x20u
#define CHCK 0x40u
#define ACTIVE_FLAGS_TYPE uint32_t
//
// Mem operations
//

struct rte_mempool* g_tcp_flow_state_pool = NULL;  // mempool for hash table values
static inline void get_mem(struct tcp_flow_state** object)  { rte_mempool_get(g_tcp_flow_state_pool, (void**)object);}
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

static struct rte_hash* g_flows;            // hash table
static void hashtable_init(struct filter_settings* settings) {
    struct rte_hash_parameters hash_params = {
            .entries = settings->flow_number,
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
}

struct additional_info_for_new_state {
    uint16_t direction;
    enum HandshakePhase phase;
};
static inline struct tcp_flow_state* at_key_or_create(struct tcp_flow_key* key, struct additional_info_for_new_state* i) {
    // Return value from hash table or return new flow_state value
    struct tcp_flow_state* flow_state;
    if (rte_hash_lookup_data(g_flows, key, (void**)&flow_state) < 0) {
        get_mem(&flow_state);
        flow_state->state = i->phase;
        flow_state->first_to_second = i->direction;
#ifdef ___TEST
        printf("ADD NEW VALUE flow_state->state: %x\n", flow_state->state);
        printf("ADD NEW VALUE flow_state->first_to_second: %x\n", flow_state->first_to_second);
        printf("ADD NEW VALUE i->phase: %x\n", i->phase);
        printf("ADD NEW VALUE i->direction: %x\n", i->direction);
#endif
    }
    return flow_state;
}

static inline uint8_t add_by_key(struct tcp_flow_key* key, struct tcp_flow_state* value) {
    // Try to add new value to hash table. Return 1 if adding was successful, 0 otherwise
    return rte_hash_add_key_data(g_flows, key, value) == 0;
}

static inline uint8_t delete_by_key(struct tcp_flow_key* key) {
    // Try to delete value by key from hash table and free mem of value. Return 1 if success, 0 otherwise
    struct tcp_flow_state* flow_state;
    if (rte_hash_lookup_data(g_flows, key, (void**)&flow_state) < 0)
        return 0;
    rte_hash_del_key(g_flows, key);
    free_mem(flow_state);
    return 1;
}

static inline void update_values(struct tcp_flow_state* values, struct tcp_hdr* new_values) {
    // Update seq and ack values for stored package
    values->ack = htonl(new_values->recv_ack);
    values->seq = htonl(new_values->sent_seq);
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

#ifdef ___BIDIRECTIONAL
    add_new_transition(LISTEN, 0x02u + CLNT, SYN_SENT_INITIATOR);

    add_new_transition(SYN_SENT_INITIATOR, 0x04u, SKIP);
    add_new_transition(SYN_SENT_INITIATOR, 0x02u + 0x10u + CHCK, SYN_SENT_RECIPIENT);
    add_new_transition(SYN_SENT_INITIATOR, 0x02u + CHCK, SYN_SENT_RECIPIENT_WOT_ACK);
    add_new_transition(SYN_SENT_INITIATOR, 0x02u + CLNT, SYN_SENT_INITIATOR_LOOP);

    add_new_transition(SYN_SENT_INITIATOR_LOOP, 0x04u, SKIP);
    add_new_transition(SYN_SENT_INITIATOR_LOOP, 0x02u + 0x10u, SYN_SENT_RECIPIENT);
    add_new_transition(SYN_SENT_INITIATOR_LOOP, 0x02u, SYN_SENT_RECIPIENT_WOT_ACK);
    add_new_transition(SYN_SENT_INITIATOR_LOOP, 0x02u + CLNT, SYN_SENT_INITIATOR);

    add_new_transition(SYN_SENT_RECIPIENT_WOT_ACK, 0x010u, SYN_SENT_RECIPIENT);
#endif

#ifndef ___BIDIRECTIONAL
    add_new_transition(LISTEN, 0x02u + CLNT, SYN_SENT_RECIPIENT);

    add_new_transition(SYN_SENT_RECIPIENT, 0x02u + CLNT, SYN_SENT_RECIPIENT_LOOP);
    add_new_transition(SYN_SENT_RECIPIENT_LOOP, 0x02u + CLNT, SYN_SENT_RECIPIENT);

    add_new_transition(SYN_SENT_RECIPIENT_LOOP, 0x10u + CLNT , ESTABLISHED);
#endif
    add_new_transition(SYN_SENT_RECIPIENT, 0x10u + CLNT , ESTABLISHED);
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

static uint8_t analyze_hdr(struct tcp_hdr* tcp_header, struct tcp_flow_key* key, uint8_t direction) {
    // Package analyzer

    struct additional_info_for_new_state i = {
            .direction = direction,
            .phase = LISTEN
    };
    struct tcp_flow_state* flow_state = at_key_or_create(key, &i);

    // accepted if it was
    if (flow_state->state == ESTABLISHED) {
#ifdef ___DEBUG
        accepted++;
        established++;
#endif
        return 1;
    }

    // analyze otherwise
    uint8_t clnt = 0x00u;
    if (flow_state->first_to_second == direction)
        clnt = CLNT;

#ifndef ___STRICT_FLAGS_EQUAL
    struct fsm_transition t = {
            .phase = flow_state->state,
            .active_flags = (tcp_header->tcp_flags & 0x02u) +  // SYN
                            (tcp_header->tcp_flags & 0x04u) +  // RST
                            (tcp_header->tcp_flags & 0x10u)    // ACK
    };
#endif

#ifdef ___STRICT_FLAGS_EQUAL
    struct fsm_transition t = {
            .phase = flow_state->state,
            .active_flags = tcp_header->tcp_flags
    };
#endif

#ifdef ___BIDIRECTIONAL
    if ((t.phase == SYN_SENT_INITIATOR || t.phase == SYN_SENT_INITIATOR_LOOP)
         && (flow_state->seq + 1 == htonl(tcp_header->recv_ack)))
        t.active_flags += CHCK;
    else if ((t.phase == SYN_SENT_RECIPIENT)
             && (flow_state->seq + 1 == htonl(tcp_header->recv_ack))
             && (flow_state->ack == htonl(tcp_header->sent_seq)))
        t.active_flags += CHCK;
#endif

#ifndef ___BIDIRECTIONAL
//    if ((t.phase == SYN_SENT_RECIPIENT || t.phase == SYN_SENT_RECIPIENT_LOOP) && t.active_flags != 0x02u)
//        if (flow_state->seq + 1 == htonl(tcp_header->sent_seq))
//            t.active_flags += CHCK;
#endif
    t.active_flags += clnt;
#ifdef ___TEST
    printf("ANALYZER tcp_header->tcp_flags: %x\n", tcp_header->tcp_flags);
    printf("ANALYZER flow_state.first_to_second: %u\n", flow_state->first_to_second);
    printf("ANALYZER direction: %u\n", direction);
    printf("ANALYZER clnt: %x\n", clnt);
    printf("ANALYZER t.active_flags: %x\n", t.active_flags);
    printf("ANALYZER flow_state->seq: %u\n", flow_state->seq);
    printf("ANALYZER flow_state->ack: %u\n", flow_state->ack);
    printf("ANALYZER tcp_header->seq: %u\n", htonl(tcp_header->sent_seq));
    printf("ANALYZER tcp_header->ack: %u\n\n", htonl(tcp_header->recv_ack));
#endif
    if (!get_next_state(&t)) {
#ifdef ___DEBUG
        dropped++;
#endif
        if (flow_state->state == LISTEN)
            free_mem(flow_state);
        return 0;
    }

    if (t.phase == SKIP) {
        delete_by_key(key);
    } else {
        flow_state->state = t.phase;
        update_values(flow_state, tcp_header);
        add_by_key(key, flow_state);
    }
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
        key.sPrt = src_addr;
    }
#ifdef ___TEST
    return 1;
#endif

    return analyze_hdr(tcp_header, &key, direction);
}
void print_stats() {
#ifdef ___DEBUG
    // Collect all stats for filter. Function for debug
    printf("Dropped: %lu\n", dropped);
    printf("Without transition: %lu\n", without_transition);
    printf("Accepted: %lu\n", accepted);
    printf("Established: %lu\n", established);
    printf("Lost: %lu\n", lost);
#endif
}

static void RunAllTests ();

void init_filter(struct filter_settings* settings) {
    hashtable_init(settings);
    mempool_init(settings);
    init_fsm();
#ifdef ___TEST
    RunAllTests();
#endif
}

//
//  Tests
//
#ifdef ___TEST

static const char* info_string = "FROM {PHASE: %x, FLAGS: %x} TO PHASE: %x\n\n";
static const char* info_string_incorrect_result = "FROM {PHASE: %x, FLAGS: %x} TO PHASE: %x\n%x != %x\n\n";
enum TARGET_RESULT_FSM {
    EXIST = 0x01u,
    NOT_EXIST = 0x00u
};
static void FSM_test (enum HandshakePhase phase_from, ACTIVE_FLAGS_TYPE active_flags, enum HandshakePhase phase_to,
                             enum TARGET_RESULT_FSM target_condition) {
    struct fsm_transition transition = {
            .phase = phase_from,
            .active_flags = active_flags
    };
    get_next_state(&transition);
    if ((transition.phase == phase_to) != target_condition)
        rte_exit(EXIT_FAILURE, info_string_incorrect_result, phase_from, active_flags, phase_to, transition.phase, phase_to);
}

static const char* algo_test_info = "\nCurrent phase: %x\nFirst direction: %u\nCurrent seq: %u\nCurrent ack: %u\nTCP flags: %x\nNew seq: %u\nNew ack: %u\nNew direction: %u\nTarget result: %x\n\n";
enum TARGET_RESULT_ALGO {
    ACCEPT = 0x01u,
    DROP = 0x00u
};
static void ALGO_test (enum HandshakePhase current_phase, uint8_t direction, uint32_t current_seq, uint32_t current_ack,
                              uint8_t flags, uint32_t new_seq, uint32_t new_ack,
                                      uint8_t new_direction, enum TARGET_RESULT_ALGO result) {
    struct tcp_flow_key key = {
            .fIp = 1,
            .sIp = 2,
            .fPrt = 1,
            .sPrt = 2
    };
    struct additional_info_for_new_state i = {
            .phase = current_phase,
            .direction = direction
    };
    struct tcp_flow_state* flow_state = at_key_or_create(&key, &i);
    flow_state->seq = current_seq;
    flow_state->ack = current_ack;
    add_by_key(&key, flow_state);
    struct tcp_hdr tcp_header = {
            .tcp_flags = flags,
            .sent_seq = htonl(new_seq),
            .recv_ack = htonl(new_ack)
    };

    if (analyze_hdr(&tcp_header, &key, new_direction) != result)
        rte_exit(EXIT_FAILURE, algo_test_info, current_phase, direction, current_seq, current_ack, flags, new_seq, new_ack, new_direction, result);

    delete_by_key(&key);
}
static void RunAllTests () {
    // Run tests for FSM and algorithm logic. Function for debug.

    // FSM transitions tests
#ifdef ___BIDIRECTIONAL
    FSM_test(LISTEN, CLNT + 0x02u, SYN_SENT_INITIATOR, EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x02u + 0x10u + CHCK, SYN_SENT_RECIPIENT, EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x02u + CLNT, SYN_SENT_INITIATOR_LOOP, EXIST);
    FSM_test(SYN_SENT_INITIATOR_LOOP, 0x02u + CLNT, SYN_SENT_INITIATOR, EXIST);
    FSM_test(SYN_SENT_RECIPIENT, CLNT + 0x10u + CHCK, ESTABLISHED, EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x02u + CHCK, SYN_SENT_RECIPIENT_WOT_ACK, EXIST);
    FSM_test(SYN_SENT_RECIPIENT_WOT_ACK, 0x10u, SYN_SENT_RECIPIENT, EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x04u, SKIP, EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x02u, SYN_SENT_RECIPIENT, NOT_EXIST);
    FSM_test(SYN_SENT_INITIATOR, 0x10u, SYN_SENT_RECIPIENT, NOT_EXIST);
    FSM_test(SYN_SENT_RECIPIENT, 0x02u + 0x10u, ESTABLISHED, NOT_EXIST);
#endif

#ifndef ___BIDIRECTIONAL

#endif
    printf("\nFSM tests OK\n\n");

    // Algo tests
#ifdef ___BIDIRECTIONAL
    ALGO_test(LISTEN, 1, 0, 0, 0x02u, 0, 0, 1, ACCEPT);
#ifdef ___STRICT_FLAGS_EQUAL
    ALGO_test(LISTEN, 1, 0, 0, 0x02u + 0x01u, 0, 0, 1, DROP);
#endif
    ALGO_test(SYN_SENT_INITIATOR, 1, 1, 0, 0x02u, 1, 2, 0, ACCEPT);
    ALGO_test(SYN_SENT_INITIATOR, 0, 1, 0, 0x02u + 0x10u, 1, 2, 0, DROP);
    ALGO_test(SYN_SENT_INITIATOR, 0, 1, 0, 0x02u + 0x10u, 1, 2, 1, ACCEPT);
    ALGO_test(SYN_SENT_RECIPIENT, 0, 1, 2, 0x10u, 2, 2, 0, ACCEPT);
    ALGO_test(SYN_SENT_RECIPIENT_WOT_ACK, 0, 0, 0, 0x10u, 0, 0, 1, ACCEPT);
    ALGO_test(SYN_SENT_INITIATOR_LOOP, 0, 0, 0, 0x02u, 0, 0, 0, ACCEPT);
    ALGO_test(SYN_SENT_RECIPIENT, 0, 0, 0, 0x10u + 0x02u, 0, 0, 0, DROP);
    ALGO_test(SYN_SENT_RECIPIENT, 1, 0, 0, 0x10u, 0, 0, 0, DROP);
    ALGO_test(SYN_SENT_INITIATOR, 1, 0, 0, 0x04u, 0, 0, 0, ACCEPT);
    ALGO_test(SYN_SENT_INITIATOR, 1, 0, 0, 0x04u, 0, 0, 1, DROP);
#endif

#ifndef ___BIDIRECTIONAL

#endif

    printf("\nAlgo tests OK\n\n");
}

#endif