// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_path_slot_mbt.c — bring-up smoke tests of the client compiled
 * against the scripted fake xquic (tests/mbt_client_tu.c, tests/fake_xquic.c). */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "fake_transport.h"
#include "fake_xquic.h"
#include "mbt_client_tu.h"
#include "oracle_abs.h"

static uint64_t g_now_us;
static unsigned g_tunnel_ready_calls;

static uint64_t
test_clock(void *ctx)
{
    (void)ctx;
    return g_now_us;
}

static void
on_tun_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)pkt;
    (void)len;
    (void)ctx;
}

static void
on_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
    g_tunnel_ready_calls++;
}

static mqvpn_client_t *
new_client(int reconnect)
{
    g_now_us = 1000000000ULL;
    g_tunnel_ready_calls = 0;
    fake_xqc_reset(1);

    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);
    mqvpn_config_set_clock(cfg, test_clock, NULL);
    mqvpn_config_set_multipath(cfg, 1);
    mqvpn_config_set_reconnect(cfg, reconnect, 1);

    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = on_tun_output;
    cbs.tunnel_config_ready = on_tunnel_config_ready;
    mqvpn_client_t *c = mqvpn_client_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    assert(c);
    return c;
}

static int
public_status(const mqvpn_client_t *c, int idx)
{
    mqvpn_path_info_t info[MQVPN_MAX_PATHS];
    int n = 0;
    assert(mqvpn_client_get_paths(c, info, MQVPN_MAX_PATHS, &n) == MQVPN_OK);
    assert(idx < n);
    return (int)info[idx].status;
}

/* connect → handshake → CONNECT-IP 200 → set_tun_active: ESTABLISHED. */
static void
establish(mqvpn_client_t *c, fake_transport_t *t)
{
    fake_transport_init(t);
    assert(mqvpn_client_add_path(c, NULL, fake_path_ops(), t, NULL) >= 0);
    assert(mqvpn_client_connect(c) == MQVPN_OK);
    fake_xqc_fire_handshake_finished();
    fake_xqc_fire_tunnel_response();
    assert(mqvpn_client_set_tun_active(c, 1, -1) == MQVPN_OK);
}

static void
smoke_connect_tunnel_establish(void)
{
    mqvpn_client_t *c = new_client(0);
    fake_transport_t t;
    memset(&fake_xqc_cmds, 0, sizeof(fake_xqc_cmds));
    establish(c, &t);

    assert(mqvpn_client_get_state(c) == MQVPN_STATE_ESTABLISHED);
    assert(public_status(c, 0) == MQVPN_PATH_ACTIVE);
    assert(fake_xqc_cmds.h3_connect == 1);
    assert(g_tunnel_ready_calls == 1);

    mqvpn_client_destroy(c);
    printf("smoke_connect_tunnel_establish OK\n");
}

static void
smoke_ready_activates_pending(void)
{
    mqvpn_client_t *c = new_client(0);
    fake_transport_t t0, t1;
    establish(c, &t0);

    fake_transport_init(&t1);
    assert(mqvpn_client_add_path(c, NULL, fake_path_ops(), &t1, NULL) >= 0);
    memset(&fake_xqc_cmds, 0, sizeof(fake_xqc_cmds));
    fake_xqc_script_create_path(0, 5);
    fake_xqc_fire_ready_to_create_path();

    assert(mbt_n_paths(c) == 2);
    assert(mbt_slot(c, 1)->xqc_path_id == 5);
    assert(mbt_slot(c, 1)->state == PATH_LC_VALIDATING);
    assert(fake_xqc_cmds.create_path == 1);

    mqvpn_client_destroy(c);
    printf("smoke_ready_activates_pending OK\n");
}

static void
smoke_peer_close_reconnects(void)
{
    mqvpn_client_t *c = new_client(1);
    fake_transport_t t;
    establish(c, &t);

    fake_xqc_fire_peer_close();
    assert(mqvpn_client_get_state(c) == MQVPN_STATE_RECONNECTING);

    g_now_us += 61ULL * 1000000;
    memset(&fake_xqc_cmds, 0, sizeof(fake_xqc_cmds));
    fake_xqc_script_connect(1);
    assert(mqvpn_client_tick(c) == MQVPN_OK);
    assert(mqvpn_client_get_state(c) == MQVPN_STATE_CONNECTING);
    assert(fake_xqc_cmds.h3_connect == 1);

    mqvpn_client_destroy(c);
    printf("smoke_peer_close_reconnects OK\n");
}

int
main(void)
{
    smoke_connect_tunnel_establish();
    smoke_ready_activates_pending();
    smoke_peer_close_reconnects();
    return 0;
}
