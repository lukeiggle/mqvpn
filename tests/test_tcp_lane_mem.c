// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_tcp_lane_mem.c — TCP-lane downlink against the REAL lwIP segment pool.
 *
 * test_tcp_lane.c substitutes tcp_write/tcp_sndbuf/tcp_output with scripted
 * doubles on stack-fake pcbs, which is right for the relay's control flow
 * but cannot show how flows interact through lwIP's shared MEMP_TCP_SEG
 * pool. This file includes the same two lane TUs with NO lwIP hooks: every
 * flow is a real pcb accepted through a real IPv4 handshake fed into
 * mqvpn_lwip_input, every downlink write is a real tcp_write, and the inner
 * host's ACKs are crafted packets. The H3 side is a per-request double: a
 * "bulk" request always has another full read buffered (a slow LAN sink
 * behind a server that keeps the stream full), a "probe" request returns
 * only what the test queues on it (a small request/response flow).
 *
 * The inner host never reads ahead: its SYN advertises a 64 KiB window and
 * carries no window-scale option, so a bulk flow has at most ~48 segments
 * in flight and the rest of what the lane writes stays on the pcb's unsent
 * queue, holding pool segments until the host ACKs.
 */
#include "hybrid/tcp_lane.c"
#include "hybrid/tcp_lane_uplink.c"

#include "hybrid/classifier.h"
#include "hybrid/lwip_glue.h"
#include "lwip/memp.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg)                                              \
    do {                                                                      \
        if ((long long)(a) == (long long)(b)) {                               \
            g_pass++;                                                         \
        } else {                                                              \
            g_fail++;                                                         \
            fprintf(stderr, "FAIL [%s]: %lld != %lld\n", msg, (long long)(a), \
                    (long long)(b));                                          \
        }                                                                     \
    } while (0)

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

/* ─── H3 doubles (real implementations live in mqvpn_client.c) ─── */

typedef struct {
    int bulk;       /* 1: a full read is always available */
    size_t pending; /* probe: bytes queued by the test, delivered once */
    uint64_t delivered;
} test_req_t;

static void *g_open_flow;

int
cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle, const mqvpn_flow_key_t *key)
{
    (void)client_ctx;
    (void)key;
    g_open_flow = flow_handle;
    return 0;
}

ssize_t
cli_tcp_lane_h3_send(void *h3_request, const uint8_t *buf, size_t len, int fin)
{
    (void)h3_request;
    (void)buf;
    (void)fin;
    return (ssize_t)len;
}

ssize_t
cli_tcp_lane_h3_recv(void *h3_request, uint8_t *buf, size_t len, int *fin)
{
    test_req_t *r = (test_req_t *)h3_request;
    *fin = 0;
    size_t n;
    if (r->bulk) {
        n = len;
    } else if (r->pending) {
        n = r->pending < len ? r->pending : len;
        r->pending -= n;
    } else {
        return MQVPN_TCP_LANE_H3_RECV_AGAIN;
    }
    memset(buf, (int)(r->delivered & 0xff), n);
    r->delivered += n;
    return (ssize_t)n;
}

void
cli_tcp_lane_h3_close(void *h3_request)
{
    (void)h3_request;
}

/* ─── clock ─── */

static uint64_t g_now_us = 1000000;

static uint64_t
test_clock(void *ctx)
{
    (void)ctx;
    return g_now_us;
}

/* ─── inner host: IPv4 packet builders and the lwIP output capture ─── */

#define HOST_IP   0x0a000001u /* 10.0.0.1, the LAN host behind the client */
#define SERVER_IP 0x5db8d822u /* 93.184.216.34, the flow's destination */
#define TUN_MTU   1382        /* a common tunnel TUN MTU: lwIP MSS 1342 */

#define MAX_PORTS 64
#define PORT_BASE 20000
static uint32_t g_synack_isn[MAX_PORTS];

static uint32_t
csum_add(const uint8_t *d, size_t len, uint32_t sum)
{
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += (uint32_t)((d[i] << 8) | d[i + 1]);
    }
    if (i < len) {
        sum += (uint32_t)(d[i] << 8);
    }
    return sum;
}

static uint16_t
csum_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void
put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t
get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Host -> server TCP segment with no payload. syn adds an MSS option. */
static size_t
build_v4(uint8_t *buf, uint16_t sport, uint32_t seq, uint32_t ack, int syn)
{
    size_t tcp_len = syn ? 24 : 20;
    size_t len = 20 + tcp_len;
    memset(buf, 0, len);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(len >> 8);
    buf[3] = (uint8_t)len;
    buf[8] = 64;
    buf[9] = 6;
    put32(buf + 12, HOST_IP);
    put32(buf + 16, SERVER_IP);
    uint16_t ipc = csum_fold(csum_add(buf, 20, 0));
    buf[10] = (uint8_t)(ipc >> 8);
    buf[11] = (uint8_t)ipc;

    uint8_t *t = buf + 20;
    t[0] = (uint8_t)(sport >> 8);
    t[1] = (uint8_t)sport;
    t[2] = 0;
    t[3] = 80;
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = (uint8_t)((tcp_len / 4) << 4);
    t[13] = syn ? TCP_SYN : TCP_ACK;
    t[14] = 0xff; /* 65535, no window scale offered */
    t[15] = 0xff;
    if (syn) {
        t[20] = 2;
        t[21] = 4;
        t[22] = 1460 >> 8;
        t[23] = 1460 & 0xff;
    }
    uint8_t ph[12];
    put32(ph, HOST_IP);
    put32(ph + 4, SERVER_IP);
    ph[8] = 0;
    ph[9] = 6;
    ph[10] = (uint8_t)(tcp_len >> 8);
    ph[11] = (uint8_t)tcp_len;
    uint16_t tc = csum_fold(csum_add(t, tcp_len, csum_add(ph, 12, 0)));
    t[16] = (uint8_t)(tc >> 8);
    t[17] = (uint8_t)tc;
    return len;
}

static void
test_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)ctx;
    if (len < 40 || (pkt[0] >> 4) != 4) {
        return;
    }
    const uint8_t *t = pkt + (pkt[0] & 0x0f) * 4;
    uint16_t dport = (uint16_t)((t[2] << 8) | t[3]);
    if ((t[13] & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && dport >= PORT_BASE &&
        dport < PORT_BASE + MAX_PORTS) {
        g_synack_isn[dport - PORT_BASE] = get32(t + 4);
    }
}

/* ─── fixture ─── */

static mqvpn_lwip_ctx_t *g_ctx;

typedef struct {
    uint16_t sport;
    uint32_t host_isn;
    test_req_t req;
    int stream; /* address used as the opaque cli_stream_t* */
    mqvpn_tcp_flow_t *f;
} test_flow_t;

static mqvpn_tcp_lane_t *
new_lane(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.enabled = 1;
    cfg.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    cfg.tcp_max_flows = 64;
    mqvpn_tcp_lane_t *lane =
        mqvpn_tcp_lane_new(&cfg, 0x6d656dULL, NULL, test_clock, NULL);
    mqvpn_lwip_ctx_set_accept_cb(g_ctx, mqvpn_tcp_lane_lwip_accept, lane);
    return lane;
}

/* Real handshake, then bind and establish the H3 side. */
static int
open_flow(mqvpn_tcp_lane_t *lane, test_flow_t *tf, uint16_t sport, int bulk)
{
    memset(tf, 0, sizeof(*tf));
    tf->sport = sport;
    tf->host_isn = 1000u + sport;
    tf->req.bulk = bulk;

    uint8_t pkt[64];
    size_t n = build_v4(pkt, sport, tf->host_isn, 0, 1);
    mqvpn_hybrid_config_t ccfg;
    mqvpn_hybrid_config_default(&ccfg);
    ccfg.enabled = 1;
    ccfg.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    mqvpn_flow_key_t key;
    if (mqvpn_hybrid_classify(pkt, n, &ccfg, &key) != MQVPN_LANE_TCP) return -1;
    if (mqvpn_tcp_lane_on_syn(lane, &key, 1, 0) != 0) return -1;
    g_synack_isn[sport - PORT_BASE] = 0;
    if (mqvpn_lwip_input(g_ctx, pkt, n) != 0) return -1;
    uint32_t sisn = g_synack_isn[sport - PORT_BASE];
    if (!sisn) return -1;
    g_open_flow = NULL;
    n = build_v4(pkt, sport, tf->host_isn + 1, sisn + 1, 0);
    if (mqvpn_lwip_input(g_ctx, pkt, n) != 0 || !g_open_flow) return -1;
    tf->f = (mqvpn_tcp_flow_t *)g_open_flow;
    mqvpn_tcp_lane_bind_h3_request(tf->f, &tf->req, &tf->stream);
    mqvpn_tcp_lane_on_stream_established(lane, &tf->stream);
    return tf->f->state == TCP_FLOW_ACTIVE ? 0 : -1;
}

/* The inner host ACKs up to `bytes` more of what lwIP has transmitted. */
static void
host_ack(test_flow_t *tf, uint32_t bytes)
{
    struct tcp_pcb *pcb = tf->f->pcb;
    uint32_t inflight = pcb->snd_nxt - pcb->lastack;
    uint32_t ackno = pcb->lastack + (bytes < inflight ? bytes : inflight);
    uint8_t pkt[64];
    size_t n = build_v4(pkt, tf->sport, tf->host_isn + 1, ackno, 0);
    (void)mqvpn_lwip_input(g_ctx, pkt, n);
}

/* Free segments left in the pool, counted up to `cap` (nothing is kept). */
static int
pool_free_segs(int cap)
{
    void *held[64];
    int n = 0;
    if (cap > 64) cap = 64;
    while (n < cap && (held[n] = memp_malloc(MEMP_TCP_SEG)) != NULL) {
        n++;
    }
    for (int i = 0; i < n; i++) {
        memp_free(MEMP_TCP_SEG, held[i]);
    }
    return n;
}

static void
pump(mqvpn_tcp_lane_t *lane, test_flow_t *tf)
{
    (void)mqvpn_tcp_lane_downlink_pump(lane, &tf->stream);
}

static void
probe_echo(mqvpn_tcp_lane_t *lane, test_flow_t *probe, size_t bytes)
{
    probe->req.pending += bytes;
    pump(lane, probe);
}

/* Deterministic stand-in for slow sinks reading at their own pace: each
 * step, one flow that holds segments is ACKed for 1..4000 more bytes. */
static uint32_t g_lcg = 1;

static uint32_t
lcg(void)
{
    g_lcg = g_lcg * 1103515245u + 12345u;
    return g_lcg >> 16;
}

static void
ack_churn_step(test_flow_t *flows, int n)
{
    for (int tries = 0; tries < 4 * n; tries++) {
        test_flow_t *tf = &flows[lcg() % (uint32_t)n];
        if (tf->f->pcb->snd_nxt != tf->f->pcb->lastack) {
            host_ack(tf, 1 + lcg() % 4000);
            return;
        }
    }
}

#define N_BULK    12
#define BULK_READ 8960 /* one cli_tcp_lane_h3_recv buffer (TCP_MSS) */
#define READ_SEGS ((BULK_READ + (TUN_MTU - 40) - 1) / (TUN_MTU - 40))

static int
open_all(mqvpn_tcp_lane_t *lane, test_flow_t *bulk, int n, test_flow_t *probe)
{
    int ok = 1;
    for (int i = 0; i < n; i++) {
        ok &= open_flow(lane, &bulk[i], (uint16_t)(PORT_BASE + i), 1) == 0;
    }
    ok &= open_flow(lane, probe, (uint16_t)(PORT_BASE + n), 0) == 0;
    return ok;
}

static int
is_stranded(const test_flow_t *tf)
{
    return tf->f->downlink_paused && tf->f->pcb->snd_queuelen == 0;
}

/* Twelve slow-sink flows exhaust the pool: at MSS 1342 a pcb reaches its own
 * TCP_SND_QUEUELEN (937) after ~1.26 MB, so 8192 segments cover fewer than
 * nine of them. The rest take ERR_MEM on their first write and hold nothing,
 * so no tcp_sent can ever arrive for them. While the holding flows' sinks
 * read, each ACK's tcp_sent refills that same flow until fewer free segments
 * remain than one read needs, so the pool sits at 0..READ_SEGS-1 free. A
 * small write that lands on 0 takes ERR_MEM and nothing but its own next
 * notify or the 1 Hz sweep retries it. */
static void
test_pool_exhaustion_strands_flows(void)
{
    mqvpn_tcp_lane_t *lane = new_lane();
    static test_flow_t bulk[N_BULK];
    static test_flow_t probe;
    int ok = open_all(lane, bulk, N_BULK, &probe);
    ASSERT_TRUE(ok, "exhaust: all flows opened through real handshakes");
    if (!ok) {
        mqvpn_tcp_lane_free(lane);
        return;
    }
    ASSERT_EQ_INT(probe.f->pcb->mss, TUN_MTU - 40, "exhaust: MSS from the TUN MTU");

    for (int i = 0; i < N_BULK; i++) {
        pump(lane, &bulk[i]);
    }
    int queued = 0, stranded = 0;
    for (int i = 0; i < N_BULK; i++) {
        queued += bulk[i].f->pcb->snd_queuelen;
        stranded += is_stranded(&bulk[i]);
    }
    ASSERT_TRUE(queued > MEMP_NUM_TCP_SEG - READ_SEGS,
                "exhaust: the slow sinks' queues hold all but < one read of the pool");
    ASSERT_TRUE(pool_free_segs(64) < READ_SEGS,
                "exhaust: fewer free segments than one read");
    ASSERT_TRUE(stranded >= 3,
                "exhaust: flows paused on their first write, holding nothing");

    /* Sinks read; find an instant with the pool empty. */
    g_lcg = 1;
    int steps = 0;
    while (pool_free_segs(1) != 0 && steps < 5000) {
        ack_churn_step(bulk, N_BULK);
        steps++;
    }
    ASSERT_EQ_INT(pool_free_segs(1), 0, "exhaust: churn reaches an empty pool");

    probe_echo(lane, &probe, 256);
    ASSERT_EQ_INT(probe.f->downlink_paused, 1, "exhaust: probe write takes ERR_MEM");
    ASSERT_EQ_INT(probe.f->pcb->snd_queuelen, 0,
                  "exhaust: probe holds nothing, no tcp_sent");

    /* Other flows' ACKs free segments; nothing retries the probe, and every
     * ACKed flow refills what it freed. */
    int saw_free = 0;
    for (int k = 0; k < 200; k++) {
        ack_churn_step(bulk, N_BULK);
        saw_free |= pool_free_segs(1);
    }
    ASSERT_TRUE(saw_free, "exhaust: segments were free between ACKs");
    ASSERT_EQ_INT(probe.f->downlink_paused, 1,
                  "exhaust: probe still paused after 200 ACKs on other flows");
    ASSERT_TRUE(pool_free_segs(64) < READ_SEGS,
                "exhaust: ACKed flows refilled what they freed");
    for (int i = 0; i < N_BULK; i++) {
        if (is_stranded(&bulk[i]) && bulk[i].f->pcb->snd_nxt != g_synack_isn[i] + 1) {
            ok = 0;
        }
    }
    ASSERT_TRUE(ok, "exhaust: stranded flows sent nothing while the others were ACKed");

    /* The sweep lets the probe out, given one free segment. */
    while (pool_free_segs(1) == 0) {
        ack_churn_step(bulk, N_BULK);
    }
    g_now_us += 1000000;
    mqvpn_tcp_lane_tick(lane, g_now_us);
    ASSERT_EQ_INT(probe.f->downlink_paused, 0, "exhaust: 1 Hz sweep flushes the probe");

    mqvpn_tcp_lane_free(lane);
}

/* A write refused because the shared pool is empty, not because the pcb
 * reached its own queue limit, bumps downlink_mem_errors and marks the flow
 * in flows_mem_blocked until its write gets in. */
static void
test_mem_blocked_counted(void)
{
    mqvpn_tcp_lane_t *lane = new_lane();
    static test_flow_t bulk[N_BULK];
    static test_flow_t probe;
    int ok = open_all(lane, bulk, N_BULK, &probe);
    ASSERT_TRUE(ok, "count: flows opened");
    if (!ok) {
        mqvpn_tcp_lane_free(lane);
        return;
    }
    for (int i = 0; i < N_BULK; i++) {
        pump(lane, &bulk[i]);
    }
    int own_limit = 0, pool_blocked = 0;
    for (int i = 0; i < N_BULK; i++) {
        if (!bulk[i].f->downlink_paused) continue;
        if (bulk[i].f->pcb->snd_queuelen + READ_SEGS + 1 > TCP_SND_QUEUELEN) {
            own_limit++;
        } else {
            pool_blocked++;
        }
    }
    mqvpn_tcp_lane_stats_t st;
    mqvpn_tcp_lane_get_stats(lane, &st);
    ASSERT_TRUE(own_limit >= 8, "count: flows at their own queue limit");
    ASSERT_TRUE(pool_blocked >= 3, "count: flows refused by the pool");
    ASSERT_EQ_INT(st.flows_paused, own_limit + pool_blocked,
                  "count: flows_paused covers both");
    ASSERT_EQ_INT(st.flows_mem_blocked, pool_blocked,
                  "count: only pool refusals are mem-blocked");
    ASSERT_EQ_INT(st.downlink_mem_errors, pool_blocked,
                  "count: one error per pool refusal");

    /* Responses end; the sinks read everything; the sweep lets the refused
     * flows' stashed reads in, and they leave the gauge. */
    for (int i = 0; i < N_BULK; i++) {
        bulk[i].req.bulk = 0;
    }
    for (int k = 0; k < 100000 && pool_free_segs(64) < 64; k++) {
        for (int i = 0; i < N_BULK; i++) {
            if (bulk[i].f->pcb->snd_nxt != bulk[i].f->pcb->lastack)
                host_ack(&bulk[i], 65535);
        }
    }
    g_now_us += 1000000;
    mqvpn_tcp_lane_tick(lane, g_now_us);
    mqvpn_tcp_lane_get_stats(lane, &st);
    ASSERT_EQ_INT(st.flows_mem_blocked, 0, "count: flushed flows leave the gauge");
    ASSERT_EQ_INT(st.flows_paused, 0, "count: nothing left paused");
    ASSERT_EQ_INT(st.downlink_mem_errors, pool_blocked, "count: the counter only grows");

    mqvpn_tcp_lane_free(lane);
}

int
main(void)
{
    g_ctx = mqvpn_lwip_ctx_new(test_clock, NULL, test_output, NULL, TUN_MTU);
    if (!g_ctx) {
        fprintf(stderr, "test_tcp_lane_mem: lwip ctx\n");
        return 1;
    }
    test_pool_exhaustion_strands_flows();
    test_mem_blocked_counted();
    ASSERT_EQ_INT(pool_free_segs(64), 64, "teardown: every test returned its segments");
    mqvpn_lwip_ctx_free(g_ctx);
    fprintf(stderr, "test_tcp_lane_mem: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
