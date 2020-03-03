#include "filter.h"
#include "rte_jhash.h"

#define ___DEBUG    // Выводит статистику по работе фильтра

//
// Вспомогательные структуры и типы
//
enum HandshakePhase {
    CLOSED = 0x00u,         
    SYN_SENT = 0x01u,       
    ESTABLISHED = 0x02u,
    FIN_SENT = 0x03u,
    FIN_ACK = 0x04u
};
struct tcp_flow_key {
    // Инвариант ключа: первый ip всегда меньше второго по значению (позволяет отслеживать прямые и обратные сообщения как один TCP flow)
    uint32_t fIp;   // first ip address
    uint32_t fPrt;  // first port
    uint32_t sIp;   // second ip address
    uint32_t sPrt;  // second port
};
struct tcp_flow_state {
    enum HandshakePhase state;
    uint16_t first_to_second; // Флаг, указывающий кто выступил источником, а кто приемником в самом перво сообщении (с флагом SYN)
    // uint32_t seq;             
};

//
// Операции с памятью в рамках работы с хэш-таблицей
//

struct rte_mempool* g_tcp_flow_state_pool = NULL;  // mempool для значений из таблицы
static inline void get_mem(struct tcp_flow_state** object) { rte_mempool_get(g_tcp_flow_state_pool, (void**)object);}
static inline void free_mem(struct tcp_flow_state* object) { rte_mempool_put(g_tcp_flow_state_pool, object); }
static void mempool_init(struct filter_settings* settings) {
    // Init mempool for hash table values
    g_tcp_flow_state_pool = rte_mempool_create("tcp_state_pool", settings->flow_number + 1000,
            sizeof(struct tcp_flow_state),0, 0, NULL, NULL,
                    NULL, NULL, (int)rte_socket_id(), 0);
}

//
//  Инициализация хэш-таблицы и функции обертки по работе с ней
//

#ifdef ___DEBUG
static uint64_t hash_table_size = 0;
static uint64_t return_default_value = 0;
static uint64_t add_new_element = 0;
static uint64_t remove_element = 0;
#endif

static uint32_t hash_tcp_key(const void* k, uint32_t length, uint32_t initval) {
    // Полиномиальная хэш-функция от значений адресов и портов участников TCP-flow
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
static struct rte_hash* g_flows;                  // hash-table
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
    if (g_flows == NULL){ rte_exit(EXIT_FAILURE, "No hash table created\n"); }
}

static inline struct tcp_flow_state* at_key_or_default(struct tcp_flow_key* key, struct tcp_flow_state* default_value) {
    // Возвращает значение по ключу из таблицы или переданное значение по умолчанию.
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
    // Добавляет в таблицу значение по ключу. Выделяет память в mempool для постоянного хранения. Возвращает 1 в случае успешного добавления, иначе 0
    struct tcp_flow_state* tmp;
    if (rte_hash_lookup_data(g_flows, key, (void**)&tmp) < 0) {
#ifdef ___DEBUG
        add_new_element++;
        hash_table_size++;
#endif
        struct tcp_flow_state* new_element;
        get_mem(&new_element);
        new_element->state = value->state;
        // new_element->seq = value->seq;
        new_element->first_to_second = value->first_to_second;

        rte_hash_add_key_data(g_flows, key, new_element);

        return 1;
    }
    return 0;
}

static inline uint8_t delete_by_key(struct tcp_flow_key* key) {
    // Удаляет значение по ключу. Высвобождает память из под него в mempool. 1 - значение удалено, 0 - нет.
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

// static inline void update_values(struct tcp_flow_state* state, struct tcp_hdr* hdr) {
//    // Update seq and ack values for stored package
//    state->seq = ntohl(hdr->sent_seq);
//}

//
// Конечный автомат распознавания стадий TCP-flow 
//


static struct rte_hash* fsm_transitions = NULL;      // Конечный автомат
struct rte_mempool* fsm_states;                      // для распознавания стадий TCP-flow

#define FIN 0x01u
#define SYN 0x02u
#define ACK 0x10u
#define BCKWD 0x80u
#define ACTIVE_FLAGS_TYPE uint32_t

struct fsm_state {
    enum HandshakePhase phase;
    ACTIVE_FLAGS_TYPE active_flags;
    // Флаги для обработки состояний. Могут включать в себя как флаги из TCP заголовка, так и пользовательские флаги.
};
static inline void add_new_transition_fwd(enum HandshakePhase phase_from, ACTIVE_FLAGS_TYPE flags_from, enum HandshakePhase phase_to) {
    // Добавить новый прямой переход. От состояния phase_from через флаги flags_from в состояние phase_to.
    struct fsm_state t = {
            .phase = phase_from,
            .active_flags = flags_from
    };
    enum HandshakePhase* s;
    rte_mempool_get(fsm_states, (void**)&s);
    *s = phase_to;
    rte_hash_add_key_data(fsm_transitions, &t, s);
}
static inline void add_new_transition_bckwd(enum HandshakePhase phase_from, enum HandshakePhase phase_to) {
    // Добавить новый обратный переход. От состояния phase_from через флаг bckwd
    struct fsm_state t = {
            .phase = phase_from,
            .active_flags = BCKWD
    };
    enum HandshakePhase* s;
    rte_mempool_get(fsm_states, (void**)&s);
    *s = phase_to;
    rte_hash_add_key_data(fsm_transitions, &t, s);
}
static inline void add_new_pass(enum HandshakePhase phase_from, ACTIVE_FLAGS_TYPE flags_from, enum HandshakePhase phase_to) {
    // Add new forward and backward pass between states in FSM of handshake parsing.
    // Forward for ordinary handshake way.
    // Backward for retransmission (repeat of package sent) processing without forgotten current state
    add_new_transition_fwd(phase_from, flags_from, phase_to);
    add_new_transition_bckwd(phase_to, phase_from);
}
static void init_fsm() {
    struct rte_hash_parameters hash_params = {
            .entries = 100,
            .key_len = sizeof(struct fsm_state),
            .socket_id = (int)rte_socket_id(),
            .hash_func_init_val = 0,
            .name = "finite state machine for tcp handshake parsing"
    };
    fsm_transitions = rte_hash_create(&hash_params);
    if (fsm_transitions == NULL) { rte_exit(EXIT_FAILURE, "No FSM created\n"); }

    fsm_states = rte_mempool_create("FSM states", 20,
                                    sizeof(enum HandshakePhase),0, 0, NULL, NULL,
                                    NULL, NULL, (int)rte_socket_id(), 0);

    // Logic of handshake parsing

    add_new_pass(CLOSED, SYN, SYN_SENT);
    add_new_pass(SYN_SENT, ACK, ESTABLISHED);
    add_new_pass(ESTABLISHED, FIN + ACK, FIN_SENT);
    add_new_pass(FIN_SENT, ACK, FIN_ACK);
}

#ifdef ___DEBUG
static uint64_t without_transition = 0;
static uint64_t dropped = 0;
static uint64_t accepted = 0;
static uint64_t established = 0;
static uint64_t lost = 0;
static uint64_t retransmission_like = 0;
static uint64_t retransmission = 0;
static uint64_t new_state = 0;
#endif

enum TransitionResult {
    DROP = 0x00u,
    RETRANSMISSION = 0x01,
    ACCEPT = 0x02u
};

static uint8_t is_retransmission(struct fsm_state* state) {
    enum HandshakePhase* tmp;
    if (rte_hash_lookup_data(fsm_transitions, state, (void**)&tmp) < 0) {
        struct fsm_state b_key = {
                .active_flags = BCKWD,
                .phase = state->phase
        };
        if (rte_hash_lookup_data(fsm_transitions, &b_key, (void**)&tmp) < 0)
            return 0;
        else {
            state->phase = *tmp;
            is_retransmission(state);
        }
    }
    return 1;
}

static enum TransitionResult get_next_state(struct fsm_state* state) {
    // Try to get next state by using FSM transitions. Update get state->phase if next state exists and return 1, otherwise 0
    enum HandshakePhase* tmp;
    if (rte_hash_lookup_data(fsm_transitions, state, (void**)&tmp) < 0) {
        struct fsm_state b_key = {
                .active_flags = BCKWD,
                .phase = state->phase
        };
        if (rte_hash_lookup_data(fsm_transitions, &b_key, (void**)&tmp) < 0) {
#ifdef ___DEBUG
            without_transition++;
            if (state->phase != CLOSED) {
                lost++;
                printf("Phase of lost: %x\nFlags of lost: %x\n\n", state->phase, state->active_flags);
            }
#endif
            return DROP;
        }
        struct fsm_state prev_state = {
                .phase = *tmp,
                .active_flags = state->active_flags
        };
#ifdef ___DEBUG
        retransmission_like++;
#endif
        return (enum TransitionResult) is_retransmission(&prev_state);
    }

    state->phase = *tmp;
    return ACCEPT;
}

//
// Логика обработки пакета
//

static inline uint8_t ordinary_msg(struct tcp_flow_state* state, struct tcp_hdr* header) {
    return (state->state == ESTABLISHED && ((header->tcp_flags & FIN) == 0)) || state->state == FIN_ACK;
}

static uint8_t analyze_hdr(struct tcp_hdr* tcp_header, struct tcp_flow_key* key, uint8_t direction) {
    // Package analyzer
    struct tcp_flow_state default_value = {
            .state = CLOSED,
            .first_to_second = direction
    };
    struct tcp_flow_state* flow_state = at_key_or_default(key, &default_value);

    // accepted if it was
    if (ordinary_msg(flow_state, tcp_header)) {
#ifdef ___DEBUG
        accepted++;
        established++;
#endif
        return 1;
    }
    // analyze otherwise
    struct fsm_state t = {
            .phase = flow_state->state,
            .active_flags = (tcp_header->tcp_flags & SYN) +  // SYN
                            (tcp_header->tcp_flags & ACK) +  // ACK
                            (tcp_header->tcp_flags & FIN)    // FIN
    };

    switch (get_next_state(&t)) {
        case DROP : {
#ifdef ___DEBUG
            dropped++;
#endif
            return 0;
        }
        case RETRANSMISSION : {
#ifdef ___DEBUG
            retransmission++;
            accepted++;
#endif
            return 1;
        }
        case ACCEPT : {
            flow_state->state = t.phase;
            if (flow_state->state == SYN_SENT)
                add_by_key(key, flow_state);
#ifdef ___DEBUG
            accepted++;
            new_state++;
#endif
            return 1;
        }
        default:
            rte_exit(EXIT_FAILURE, "ERROR:: Unconditional state");
    }
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
    printf("New state: %lu\n", new_state);
    printf("Established: %lu\n", established);
    printf("Lost: %lu\n", lost);
    printf("Retransmission like: %lu\n", retransmission_like);
    printf("Retransmission: %lu\n", retransmission);
    printf("Hash table size: %lu\n", hash_table_size);
    printf("Hash table; add new element: %lu\n", add_new_element);
    printf("Hash table; return default value: %lu\n", return_default_value);
    printf("Hash table; remove element: %lu\n", remove_element);
#endif
}

static void RunAllTests ();

void init_filter(struct filter_settings* settings) {
    init_fsm();
    hashtable_init(settings);
    mempool_init(settings);
}
