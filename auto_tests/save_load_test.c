/* Tests that we can save and load Tox data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_struct.h" // IWYU pragma: keep
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

#ifdef TOX_LOCALHOST
#undef TOX_LOCALHOST
#endif
#if USE_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

#ifdef TCP_RELAY_PORT
#undef TCP_RELAY_PORT
#endif
#define TCP_RELAY_PORT 33431

static void accept_friend_request(const Tox_Event_Friend_Request *event, void *userdata)
{
    Tox *tox = (Tox *)userdata;

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *message = tox_event_friend_request_get_message(event);
    uint32_t message_length = tox_event_friend_request_get_message_length(event);

    if (message_length == 7 && memcmp("Gentoo", message, 7) == 0) {
        tox_friend_add_norequest(tox, public_key, nullptr);
    }
}

static unsigned int connected_t1;
static void tox_connection_status(const Tox_Event_Self_Connection_Status *event, void *user_data)
{
    const Tox_Connection connection_status = tox_event_self_connection_status_get_connection_status(event);

    if (connected_t1 && !connection_status) {
        ck_abort_msg("Tox went offline");
    }

    ck_assert_msg(connection_status != TOX_CONNECTION_NONE, "wrong status %u", connection_status);

    connected_t1 = connection_status;
}

/* validate that:
 * a) saving stays within the confined space
 * b) a saved state can be loaded back successfully
 * c) a second save is of equal size
 * d) the second save is of equal content */
static void reload_tox(Tox **tox, struct Tox_Options *const in_opts, void *user_data)
{
    const size_t extra = 64;
    const size_t save_size1 = tox_get_savedata_size(*tox);
    ck_assert_msg(save_size1 != 0, "save is invalid size %u", (unsigned)save_size1);
    printf("%u\n", (unsigned)save_size1);

    uint8_t *buffer = (uint8_t *)malloc(save_size1 + 2 * extra);
    ck_assert_msg(buffer != nullptr, "malloc failed");
    memset(buffer, 0xCD, extra);
    memset(buffer + extra + save_size1, 0xCD, extra);
    tox_get_savedata(*tox, buffer + extra);
    tox_kill(*tox);

    for (size_t i = 0; i < extra; ++i) {
        ck_assert_msg(buffer[i] == 0xCD, "Buffer underwritten from tox_get_savedata() @%u", (unsigned)i);
        ck_assert_msg(buffer[extra + save_size1 + i] == 0xCD, "Buffer overwritten from tox_get_savedata() @%u", (unsigned)i);
    }

    struct Tox_Options *const options = (in_opts == nullptr) ? tox_options_new(nullptr) : in_opts;
    tox_options_set_ipv6_enabled(options, USE_IPV6);

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    ck_assert(tox_options_set_savedata(options, buffer + extra, save_size1));

    *tox = tox_new_log(options, nullptr, user_data);

    if (in_opts == nullptr) {
        tox_options_free(options);
    }

    ck_assert_msg(*tox != nullptr, "Failed to load back stored buffer");

    const size_t save_size2 = tox_get_savedata_size(*tox);

    ck_assert_msg(save_size1 == save_size2, "Tox save data changed in size from a store/load cycle: %u -> %u",
                  (unsigned)save_size1, (unsigned)save_size2);

    uint8_t *buffer2 = (uint8_t *)malloc(save_size2);

    ck_assert_msg(buffer2 != nullptr, "malloc failed");

    tox_get_savedata(*tox, buffer2);

    ck_assert_msg(!memcmp(buffer + extra, buffer2, save_size2), "Tox state changed by store/load/store cycle");

    free(buffer2);

    free(buffer);
}

typedef struct Time_Data {
    pthread_mutex_t lock;
    uint64_t clock;
} Time_Data;

static uint64_t get_state_clock_callback(void *user_data)
{
    Time_Data *time_data = (Time_Data *)user_data;
    pthread_mutex_lock(&time_data->lock);
    uint64_t clock = time_data->clock;
    pthread_mutex_unlock(&time_data->lock);
    return clock;
}

static void increment_clock(Time_Data *time_data, uint64_t count)
{
    pthread_mutex_lock(&time_data->lock);
    time_data->clock += count;
    pthread_mutex_unlock(&time_data->lock);
}

static void set_current_time_callback(Tox *tox, Time_Data *time_data)
{
    Mono_Time *mono_time = tox->mono_time;
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, time_data);
}

static void test_few_clients(void)
{
    uint32_t index[] = { 1, 2, 3 };
    time_t con_time = 0, cur_time = time(nullptr);

    struct Tox_Options *opts1 = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts1, USE_IPV6);
    tox_options_set_tcp_port(opts1, TCP_RELAY_PORT);
    Tox_Err_New t_n_error;
    Tox *tox1 = tox_new_log(opts1, &t_n_error, &index[0]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "Failed to create tox instance: %u", t_n_error);
    tox_options_free(opts1);
    tox_events_init(tox1);
    Tox_Dispatch *dispatch1 = tox_dispatch_new(nullptr);
    ck_assert(dispatch1 != nullptr);

    struct Tox_Options *opts2 = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts2, USE_IPV6);
    tox_options_set_udp_enabled(opts2, false);
    tox_options_set_local_discovery_enabled(opts2, false);
    Tox *tox2 = tox_new_log(opts2, &t_n_error, &index[1]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "Failed to create tox instance: %u", t_n_error);
    tox_events_init(tox2);
    Tox_Dispatch *dispatch2 = tox_dispatch_new(nullptr);
    ck_assert(dispatch2 != nullptr);

    struct Tox_Options *opts3 = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts3, USE_IPV6);
    tox_options_set_local_discovery_enabled(opts3, false);
    Tox *tox3 = tox_new_log(opts3, &t_n_error, &index[2]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "Failed to create tox instance: %u", t_n_error);

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    Time_Data time_data;
    ck_assert_msg(pthread_mutex_init(&time_data.lock, nullptr) == 0, "Failed to init time_data mutex");
    time_data.clock = current_time_monotonic(tox1->mono_time);
    set_current_time_callback(tox1, &time_data);
    set_current_time_callback(tox2, &time_data);
    set_current_time_callback(tox3, &time_data);

    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    printf("using tox1 as tcp relay for tox2\n");
    tox_add_tcp_relay(tox2, TOX_LOCALHOST, TCP_RELAY_PORT, dht_key, nullptr);

    printf("bootstrapping toxes off tox1\n");
    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(tox3, "localhost", dht_port, dht_key, nullptr);

    connected_t1 = 0;
    tox_events_callback_self_connection_status(dispatch1, tox_connection_status);
    tox_events_callback_friend_request(dispatch2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %u", test);

    uint8_t off = 1;

    while (true) {
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox1, true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            tox_dispatch_invoke(dispatch1, events, tox1);
            tox_events_free(events);
        }
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox2, true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            tox_dispatch_invoke(dispatch2, events, tox2);
            tox_events_free(events);
        }
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_TCP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_TCP) {
                break;
            }
        }

        increment_clock(&time_data, 200);
        c_sleep(5);
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    // We're done with this callback, so unset it to ensure we don't fail the
    // test if tox1 goes offline while tox2 and 3 are reloaded.
    tox_events_callback_self_connection_status(dispatch1, nullptr);

    reload_tox(&tox2, opts2, &index[1]);
    tox_events_init(tox2);

    reload_tox(&tox3, opts3, &index[2]);

    cur_time = time(nullptr);

    off = 1;

    while (true) {
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox1, true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            tox_dispatch_invoke(dispatch1, events, tox1);
            tox_events_free(events);
        }
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox2, true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            tox_dispatch_invoke(dispatch2, events, tox2);
            tox_events_free(events);
        }
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online again after reloading, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_TCP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_TCP) {
                break;
            }
        }

        increment_clock(&time_data, 100);
        c_sleep(5);
    }

    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    printf("test_few_clients succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));

    tox_dispatch_free(dispatch1);
    tox_dispatch_free(dispatch2);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);

    tox_options_free(opts2);
    tox_options_free(opts3);
}

static void friend_message_received(const Tox_Event_Friend_Message *event, void *user_data)
{
    bool *got_message = (bool *)user_data;
    *got_message = true;
}

/** Test that messages can be exchanged after save/load cycle */
static void test_save_load_messaging(void)
{
    printf("=== Test: save/load preserves ability to exchange messages ===\n");

    Tox_Options *opts1 = tox_options_new(nullptr);
    ck_assert(opts1 != nullptr);
    tox_options_set_local_discovery_enabled(opts1, false);
    tox_options_set_start_port(opts1, 33501);
    tox_options_set_end_port(opts1, 33501);

    Tox_Options *opts2 = tox_options_new(nullptr);
    ck_assert(opts2 != nullptr);
    tox_options_set_local_discovery_enabled(opts2, false);
    tox_options_set_start_port(opts2, 33551);
    tox_options_set_end_port(opts2, 33551);

    Tox_Err_New err1, err2;
    Tox *tox1 = tox_new(opts1, &err1);
    ck_assert(err1 == TOX_ERR_NEW_OK);
    Tox *tox2 = tox_new(opts2, &err2);
    ck_assert(err2 == TOX_ERR_NEW_OK);

    Tox_Dispatch *dispatch1 = tox_dispatch_new(nullptr);
    ck_assert(dispatch1 != nullptr);
    Tox_Dispatch *dispatch2 = tox_dispatch_new(nullptr);
    ck_assert(dispatch2 != nullptr);

    tox_events_callback_friend_request(dispatch1, accept_friend_request);
    tox_events_callback_friend_request(dispatch2, accept_friend_request);

    // Bootstrap
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox2, dht_key);
    uint16_t port2 = tox_self_get_udp_port(tox2, nullptr);
    tox_bootstrap(tox1, TOX_LOCALHOST, port2, dht_key, nullptr);

    // Add friend
    Tox_Err_Friend_Add friend_err;
    tox_friend_add(tox1, tox_self_get_address(tox2), (const uint8_t *)"test", 4, &friend_err);
    ck_assert(friend_err == TOX_ERR_FRIEND_ADD_OK);

    // Wait for connection
    time_t start_time = time(nullptr);
    while (!tox_self_get_connection_status(tox1) || !tox_self_get_connection_status(tox2)) {
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox1, true, &err);
            tox_dispatch_invoke(dispatch1, events, tox1);
            tox_events_free(events);
        }
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(tox2, true, &err);
            tox_dispatch_invoke(dispatch2, events, tox2);
            tox_events_free(events);
        }
        c_sleep(50);
        ck_assert_msg(time(nullptr) - start_time < 60, "timeout waiting for connection");
    }

    printf("  Connected. Sending message before save...\n");

    // Register message callback on tox2
    bool got_message_before_save = false;
    tox_events_callback_friend_message(dispatch2, friend_message_received);

    // Send a message from tox1 to tox2
    Tox_Err_Friend_Send_Message send_err;
    tox_friend_send_message(tox1, 0, TOX_MESSAGE_TYPE_NORMAL,
        (const uint8_t *)"Hello before save", 18, &send_err);
    ck_assert(send_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

    // Wait for delivery
    start_time = time(nullptr);
    while (!got_message_before_save) {
        Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
        Tox_Events *events = tox_events_iterate(tox2, true, &err);
        tox_dispatch_invoke(dispatch2, events, tox2);
        tox_events_free(events);
        c_sleep(50);
        ck_assert_msg(time(nullptr) - start_time < 10, "timeout waiting for message before save");
    }

    printf("  Message delivered before save. Saving both instances...\n");

    // Save both instances
    size_t save_size1 = tox_get_savedata_size(tox1);
    size_t save_size2 = tox_get_savedata_size(tox2);
    VLA(uint8_t, save_data1, save_size1);
    VLA(uint8_t, save_data2, save_size2);
    tox_get_savedata(tox1, save_data1);
    tox_get_savedata(tox2, save_data2);

    // Kill old instances
    tox_kill(tox1);
    tox_kill(tox2);
    tox_dispatch_free(dispatch1);
    tox_dispatch_free(dispatch2);

    printf("  Old instances killed. Reloading from save data...\n");

    // Reload from save data
    Tox_Options *reload_opts1 = tox_options_new(nullptr);
    ck_assert(reload_opts1 != nullptr);
    tox_options_set_savedata_data(reload_opts1, save_data1, save_size1);
    tox_options_set_local_discovery_enabled(reload_opts1, false);
    tox_options_set_start_port(reload_opts1, 33502);
    tox_options_set_end_port(reload_opts1, 33502);

    Tox_Options *reload_opts2 = tox_options_new(nullptr);
    ck_assert(reload_opts2 != nullptr);
    tox_options_set_savedata_data(reload_opts2, save_data2, save_size2);
    tox_options_set_local_discovery_enabled(reload_opts2, false);
    tox_options_set_start_port(reload_opts2, 33552);
    tox_options_set_end_port(reload_opts2, 33552);

    Tox *retox1 = tox_new(reload_opts1, &err1);
    ck_assert(err1 == TOX_ERR_NEW_OK);
    Tox *retox2 = tox_new(reload_opts2, &err2);
    ck_assert(err2 == TOX_ERR_NEW_OK);

    Tox_Dispatch *redispatch1 = tox_dispatch_new(nullptr);
    Tox_Dispatch *redispatch2 = tox_dispatch_new(nullptr);
    ck_assert(redispatch1 != nullptr && redispatch2 != nullptr);

    tox_events_callback_friend_request(redispatch1, accept_friend_request);
    tox_events_callback_friend_request(redispatch2, accept_friend_request);

    // Re-bootstrap
    tox_self_get_dht_id(retox2, dht_key);
    port2 = tox_self_get_udp_port(retox2, nullptr);
    tox_bootstrap(retox1, TOX_LOCALHOST, port2, dht_key, nullptr);

    // Wait for reconnection
    start_time = time(nullptr);
    while (!tox_self_get_connection_status(retox1) || !tox_self_get_connection_status(retox2)) {
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(retox1, true, &err);
            tox_dispatch_invoke(redispatch1, events, retox1);
            tox_events_free(events);
        }
        {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(retox2, true, &err);
            tox_dispatch_invoke(redispatch2, events, retox2);
            tox_events_free(events);
        }
        c_sleep(50);
        ck_assert_msg(time(nullptr) - start_time < 60, "timeout waiting for reconnection after reload");
    }

    printf("  Reconnected after reload. Sending message...\n");

    // Verify friend relationship survived reload
    ck_assert(tox_friend_get_connection_status(retox1, 0, nullptr) != TOX_CONNECTION_NONE);

    // Send a new message after reload
    bool got_message_after_reload = false;
    tox_events_callback_friend_message(redispatch2, friend_message_received);

    tox_friend_send_message(retox1, 0, TOX_MESSAGE_TYPE_NORMAL,
        (const uint8_t *)"Hello after reload", 19, &send_err);
    ck_assert(send_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

    // Wait for delivery after reload
    start_time = time(nullptr);
    while (!got_message_after_reload) {
        Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
        Tox_Events *events = tox_events_iterate(retox2, true, &err);
        tox_dispatch_invoke(redispatch2, events, retox2);
        tox_events_free(events);
        c_sleep(50);
        ck_assert_msg(time(nullptr) - start_time < 10, "timeout waiting for message after reload");
    }

    printf("  Message delivered after reload! Test passed.\n");

    // Cleanup
    tox_kill(retox1);
    tox_kill(retox2);
    tox_dispatch_free(redispatch1);
    tox_dispatch_free(redispatch2);
    tox_options_free(reload_opts1);
    tox_options_free(reload_opts2);
    tox_options_free(opts1);
    tox_options_free(opts2);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_few_clients();
    test_save_load_messaging();
    return 0;
}
