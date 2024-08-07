/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * Development of the code in this file was sponsored by Microbric Pty Ltd
 * and Mnemote Pty Ltd
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016, 2017 Nick Moore @mnemote
 * Copyright (c) 2017 "Eric Poulsen" <eric@zyxod.com>
 *
 * Based on esp8266/modnetwork.c which is Copyright (c) 2015 Paul Sokolovsky
 * And the ESP IDF example code which is Public Domain / CC0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <string.h>

#include "py/objlist.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "extmod/modnetwork.h"
#include "modnetwork.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_psram.h"

#ifndef NO_QSTR
#include "mdns.h"
#endif

#if MICROPY_PY_NETWORK_WLAN

#if (WIFI_MODE_STA & WIFI_MODE_AP != WIFI_MODE_NULL || WIFI_MODE_STA | WIFI_MODE_AP != WIFI_MODE_APSTA)
#error WIFI_MODE_STA and WIFI_MODE_AP are supposed to be bitfields!
#endif

typedef base_if_obj_t wlan_if_obj_t;

static wlan_if_obj_t wlan_sta_obj;
static wlan_if_obj_t wlan_ap_obj;

// Set to "true" if esp_wifi_start() was called
static bool wifi_started = false;

// Set to "true" if the STA interface is requested to be connected by the
// user, used for automatic reassociation.
static bool wifi_sta_connect_requested = false;

// Set to "true" if the STA interface is connected to wifi and has IP address.
static bool wifi_sta_connected = false;

// Store the current status. 0 means None here, safe to do so as first enum value is WIFI_REASON_UNSPECIFIED=1.
static uint8_t wifi_sta_disconn_reason = 0;

// Set to "true" if there is an in-progress background scan
static bool scan_in_progress = false;

/// TODO: These were garbage collected so they needed to be moved into root pointers. Normally they would then be accessed with
//  MP_STATE_PORT(variable_name). For some reason that isn't working, so I manually expanded the MP_STATE_PORT macro to mp_state_ctx.vm.variable_name

// A list to hold the remaining channels to scan
// static mp_obj_t remaining_channels;

// // A list for the last scan results
// static mp_obj_t last_scan_aps;

// // A temporary list for storing the partial scan results between channel scans
// static mp_obj_t partial_scan_aps;

// The wifi scan config, so that the scan_done event can properly use it
static wifi_scan_config_t scanning_config;

#if MICROPY_HW_ENABLE_MDNS_QUERIES || MICROPY_HW_ENABLE_MDNS_RESPONDER
// Whether mDNS has been initialised or not
static bool mdns_initialised = false;
#endif

static uint8_t conf_wifi_sta_reconnects = 0;
static uint8_t wifi_sta_reconnects;

// Declare the function here for the scan_done_cb to work properly
static void read_wifi_scan_results(void);

// This callback is scheduled by the WIFI_EVENT_SCAN_DONE, so that the execution happens outside of the system thread task, and has the micro-python context.
static mp_obj_t scan_done_cb(mp_obj_t arg){
    ESP_LOGI("wifi_blocking_mod", "Now inside of the scan_done_callback");
    // Save the new partial scan results to the list. This also frees the allocated memory from esp-idf
    read_wifi_scan_results();
    ESP_LOGI("wifi_blocking_mod", "Got the latest scan results");
    // See if there are any more channels that need to be scanned
    ESP_LOGE("wifi_blocking_mod", "checking if the remaining lists is an object");
    if(!mp_obj_is_obj(mp_state_ctx.vm.remaining_channels)){
        ESP_LOGE("wifi_blocking_mod", "The remaining_channels was not a real micropython object, recreating a new empty list");
        mp_state_ctx.vm.remaining_channels = mp_obj_new_list(0, NULL);
    } else {
        ESP_LOGE("wifi_blocking_mod", "The remaining_channels was an object?");
        ESP_LOGE("wifi_blocking_mod", "Type %s", mp_obj_get_type_str(mp_state_ctx.vm.remaining_channels));
    }
    ESP_LOGI("wifi_blocking_mod", "Getting the length of the remaining_channels");
    int channel_count = mp_obj_get_int(mp_obj_len(mp_state_ctx.vm.remaining_channels));
    ESP_LOGI("wifi_blocking_mod", "The length value is %d", channel_count);
    if (channel_count > 0){
        ESP_LOGI("wifi_blocking_mod", "There are still channels that need scanning!");
        // If we are here, it is safe to assume at least 1 item in the list
        mp_obj_t *channels;
        unsigned int channels_len;
        ESP_LOGI("wifi_blocking_mod", "Getting the next channel from the remaining_channels list");
        mp_obj_get_array(mp_state_ctx.vm.remaining_channels, &channels_len, &channels);
        if (channels_len == 0){
            mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("Something wrong here?"));
        }
        ESP_LOGI("wifi_blocking_mod", "Setting the configuration to have channel %ld", mp_obj_get_int(channels[0]));
        scanning_config.channel = mp_obj_get_int(channels[0]);
        ESP_LOGI("wifi_blocking_mod", "Removing the channel from remaining_channels");
        mp_obj_list_remove(mp_state_ctx.vm.remaining_channels, channels[0]);
        ESP_LOGI("wifi_blocking_mod", "Starting the scan on the new channel");
        MP_THREAD_GIL_EXIT();
        // Don't block even if the original was blocking because that is doing busy wait
        esp_err_t status = esp_wifi_scan_start(&scanning_config, 0);
        MP_THREAD_GIL_ENTER();
        esp_exceptions(status);
    } else {
        ESP_LOGI("wifi_blocking_mod", "There are no channels that need scanning, so we are done");
        ESP_LOGI("wifi_blocking_mod", "Setting the last_scan_aps to the partial_scan_aps");
        mp_state_ctx.vm.last_scan_aps = mp_state_ctx.vm.partial_scan_aps;
        ESP_LOGI("wifi_blocking_mod", "Clearing the scan_in_progress flag");
        scan_in_progress = false;
        // TODO: If there was a callback, and this was a background scan, make the call to the callback function
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_scan_done_cb_obj, scan_done_cb);

// This function is called by the system-event task and so runs in a different
// thread to the main MicroPython task.  It must not raise any Python exceptions.
static void network_wlan_wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI("wifi", "STA_START");
            wlan_sta_obj.active = true;
            wifi_sta_reconnects = 0;
            break;

        case WIFI_EVENT_STA_STOP:
            wlan_sta_obj.active = false;
            break;

        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI("network", "CONNECTED");
            break;

        case WIFI_EVENT_STA_DISCONNECTED: {
            // This is a workaround as ESP32 WiFi libs don't currently
            // auto-reassociate.

            wifi_event_sta_disconnected_t *disconn = event_data;
            char *message = "";
            wifi_sta_disconn_reason = disconn->reason;
            switch (disconn->reason) {
                case WIFI_REASON_BEACON_TIMEOUT:
                    // AP has dropped out; try to reconnect.
                    message = "beacon timeout";
                    break;
                case WIFI_REASON_NO_AP_FOUND:
                    // AP may not exist, or it may have momentarily dropped out; try to reconnect.
                    message = "no AP found";
                    break;
                #if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0)
                case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
                    // No AP with RSSI within given threshold exists, or it may have momentarily dropped out; try to reconnect.
                    message = "no AP with RSSI within threshold found";
                    break;
                case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
                    // No AP with authmode within given threshold exists, or it may have momentarily dropped out; try to reconnect.
                    message = "no AP with authmode within threshold found";
                    break;
                case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
                    // No AP with compatible security exists, or it may have momentarily dropped out; try to reconnect.
                    message = "no AP with compatible security found";
                    break;
                #endif
                case WIFI_REASON_AUTH_FAIL:
                    // Password may be wrong, or it just failed to connect; try to reconnect.
                    message = "authentication failed";
                    break;
                default:
                    // Let other errors through and try to reconnect.
                    break;
            }
            ESP_LOGI("wifi", "STA_DISCONNECTED, reason:%d:%s", disconn->reason, message);

            wifi_sta_connected = false;
            if (wifi_sta_connect_requested) {
                wifi_mode_t mode;
                if (esp_wifi_get_mode(&mode) != ESP_OK) {
                    break;
                }
                if (!(mode & WIFI_MODE_STA)) {
                    break;
                }
                if (conf_wifi_sta_reconnects) {
                    ESP_LOGI("wifi", "reconnect counter=%d, max=%d",
                        wifi_sta_reconnects, conf_wifi_sta_reconnects);
                    if (++wifi_sta_reconnects >= conf_wifi_sta_reconnects) {
                        break;
                    }
                }
                esp_err_t e = esp_wifi_connect();
                if (e != ESP_OK) {
                    ESP_LOGI("wifi", "error attempting to reconnect: 0x%04x", e);
                }
            }
            break;
        }

        case WIFI_EVENT_AP_START:
            wlan_ap_obj.active = true;
            break;

        case WIFI_EVENT_AP_STOP:
            wlan_ap_obj.active = false;
            break;

        case WIFI_EVENT_SCAN_DONE:
            // When a scan is done, schedule the callback function to handle the rest of the work since it needs to be done in the micro python context
            // instead of the system event context.
            ESP_LOGI("wifi_blocking_mod", "got wifi scan done event");
            mp_sched_schedule(MP_OBJ_FROM_PTR(&network_wlan_scan_done_cb_obj), mp_const_none);
            break;

        default:
            break;
    }
}

static void network_wlan_ip_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    switch (event_id) {
        case IP_EVENT_STA_GOT_IP:
            ESP_LOGI("network", "GOT_IP");
            wifi_sta_connected = true;
            wifi_sta_disconn_reason = 0; // Success so clear error. (in case of new error will be replaced anyway)
            #if MICROPY_HW_ENABLE_MDNS_QUERIES || MICROPY_HW_ENABLE_MDNS_RESPONDER
            if (!mdns_initialised) {
                mdns_init();
                #if MICROPY_HW_ENABLE_MDNS_RESPONDER
                mdns_hostname_set(mod_network_hostname_data);
                mdns_instance_name_set(mod_network_hostname_data);
                #endif
                mdns_initialised = true;
            }
            #endif
            break;

        default:
            break;
    }
}

static void require_if(mp_obj_t wlan_if, int if_no) {
    wlan_if_obj_t *self = MP_OBJ_TO_PTR(wlan_if);
    if (self->if_id != if_no) {
        mp_raise_msg(&mp_type_OSError, if_no == ESP_IF_WIFI_STA ? MP_ERROR_TEXT("STA required") : MP_ERROR_TEXT("AP required"));
    }
}

void esp_initialise_wifi(void) {
    static int wifi_initialized = 0;
    /// TODO: This is extraordinary scuffed? Like ultra not how this is supposed to work.
    // The micropython soft reset clears all of the python VMs variables.
    // This leads to the global references for the following variables to be pointing at uninitialized memory.
    // This memory can and repeatedly does "appear" like a valid python object, and even a valid list sometimes.
    // Therefore it cannot just be simply checked as far as I can tell. While the python VM has it's state cleared, 
    // the global variables for this code are not cleared IE the variable `wifi_initalized`. Therefore, on the new
    // running of the main loop, a wifi initialization occurs, but does nothing as the wifi_initialized is already true.
    // This would cause creating these values inside of the if statement to break, leaving un initialized memory.
    // This is a jank quick fix that anytime `network.WLAN()` is called, it will re-init these variables. If this method
    // is called more than once it WILL cause some weirdness around a multi-channel scan. Specifically, it will likely cause 
    // the scan to stop right away as there are no longer new channels to scan, clear the partially saved APs, and reset
    // the aps seen in the last scan. I have no clue how to handle this properly at 1AM, so 🤷‍♀️.
    // In other places there is deinit_all, that handles something around a soft reboot. I do not entirely understand what
    // those pieces of code are doing, and how it actually makes it work correctly around having the global python objects
    // deleted without. My best guess is that once the variables are set it turns a global flag like `wifi_initalized` to false
    // triggering the re-creation of the variables on the next init process, where that same flag gets set to true causing
    // further inits to not re-create those.
    ESP_LOGE("mod_blocking", "esp_initialise_wifi was called");
    // Create the remaining channels list
    mp_state_ctx.vm.remaining_channels = mp_obj_new_list(0, NULL);
    ESP_LOGE("mod_blocking", "Allocated the remaining_channels as an empty list");
    // Create a list for the partial scan
    mp_state_ctx.vm.partial_scan_aps = mp_obj_new_list(0, NULL);
    ESP_LOGE("mod_blocking", "Allocated the partial_scan_aps as an emtpy list");
    // Allocate that there are no aps in the last scan
    mp_state_ctx.vm.last_scan_aps = mp_const_none;
    ESP_LOGE("mod_blocking", "Allocated the last_scan_aps as a None object");
    if (!wifi_initialized) {
        esp_exceptions(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, network_wlan_wifi_event_handler, NULL, NULL));
        esp_exceptions(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, network_wlan_ip_event_handler, NULL, NULL));

        wlan_sta_obj.base.type = &esp_network_wlan_type;
        wlan_sta_obj.if_id = ESP_IF_WIFI_STA;
        wlan_sta_obj.netif = esp_netif_create_default_wifi_sta();
        wlan_sta_obj.active = false;

        wlan_ap_obj.base.type = &esp_network_wlan_type;
        wlan_ap_obj.if_id = ESP_IF_WIFI_AP;
        wlan_ap_obj.netif = esp_netif_create_default_wifi_ap();
        wlan_ap_obj.active = false;

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        #if CONFIG_SPIRAM_IGNORE_NOTFOUND
        if (!esp_psram_is_initialized()) {
            // If PSRAM failed to initialize, disable "Wi-Fi Cache TX Buffers"
            // (default SPIRAM config ESP32_WIFI_CACHE_TX_BUFFER_NUM==32, this is 54,400 bytes of heap)
            cfg.cache_tx_buf_num = 0;
            cfg.feature_caps &= ~CONFIG_FEATURE_CACHE_TX_BUF_BIT;

            // Set some other options back to the non-SPIRAM default values
            // to save more RAM.
            //
            // These can be determined from ESP-IDF components/esp_wifi/Kconfig and the
            // WIFI_INIT_CONFIG_DEFAULT macro
            cfg.tx_buf_type = 1; // Dynamic, this "magic number" is defined in IDF KConfig
            cfg.static_tx_buf_num = 0; // Probably don't need, due to tx_buf_type
            cfg.dynamic_tx_buf_num = 32; // ESP-IDF default value (maximum)
        }
        #endif
        ESP_LOGD("modnetwork", "Initializing WiFi");
        esp_exceptions(esp_wifi_init(&cfg));
        esp_exceptions(esp_wifi_set_storage(WIFI_STORAGE_RAM));

        ESP_LOGD("modnetwork", "Initialized");
        wifi_initialized = 1;
    }
}

static mp_obj_t network_wlan_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);

    esp_initialise_wifi();

    int idx = (n_args > 0) ? mp_obj_get_int(args[0]) : ESP_IF_WIFI_STA;
    if (idx == ESP_IF_WIFI_STA) {
        return MP_OBJ_FROM_PTR(&wlan_sta_obj);
    } else if (idx == ESP_IF_WIFI_AP) {
        return MP_OBJ_FROM_PTR(&wlan_ap_obj);
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid WLAN interface identifier"));
    }
}

static mp_obj_t network_wlan_active(size_t n_args, const mp_obj_t *args) {
    wlan_if_obj_t *self = MP_OBJ_TO_PTR(args[0]);

    wifi_mode_t mode;
    if (!wifi_started) {
        mode = WIFI_MODE_NULL;
    } else {
        esp_exceptions(esp_wifi_get_mode(&mode));
    }

    int bit = (self->if_id == ESP_IF_WIFI_STA) ? WIFI_MODE_STA : WIFI_MODE_AP;

    if (n_args > 1) {
        bool active = mp_obj_is_true(args[1]);
        mode = active ? (mode | bit) : (mode & ~bit);
        if (mode == WIFI_MODE_NULL) {
            if (wifi_started) {
                esp_exceptions(esp_wifi_stop());
                wifi_started = false;
            }
        } else {
            esp_exceptions(esp_wifi_set_mode(mode));
            if (!wifi_started) {
                esp_exceptions(esp_wifi_start());
                wifi_started = true;
            }
        }

        // Wait for the interface to be in the correct state.
        while (self->active != active) {
            MICROPY_EVENT_POLL_HOOK;
        }
    }

    return (mode & bit) ? mp_const_true : mp_const_false;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(network_wlan_active_obj, 1, 2, network_wlan_active);

static mp_obj_t network_wlan_connect(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum { ARG_ssid, ARG_key, ARG_bssid };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_, MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_, MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_bssid, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = mp_const_none} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    wifi_config_t wifi_sta_config = {0};

    // configure any parameters that are given
    if (n_args > 1) {
        size_t len;
        const char *p;
        if (args[ARG_ssid].u_obj != mp_const_none) {
            p = mp_obj_str_get_data(args[ARG_ssid].u_obj, &len);
            memcpy(wifi_sta_config.sta.ssid, p, MIN(len, sizeof(wifi_sta_config.sta.ssid)));
        }
        if (args[ARG_key].u_obj != mp_const_none) {
            p = mp_obj_str_get_data(args[ARG_key].u_obj, &len);
            memcpy(wifi_sta_config.sta.password, p, MIN(len, sizeof(wifi_sta_config.sta.password)));
        }
        if (args[ARG_bssid].u_obj != mp_const_none) {
            p = mp_obj_str_get_data(args[ARG_bssid].u_obj, &len);
            if (len != sizeof(wifi_sta_config.sta.bssid)) {
                mp_raise_ValueError(NULL);
            }
            wifi_sta_config.sta.bssid_set = 1;
            memcpy(wifi_sta_config.sta.bssid, p, sizeof(wifi_sta_config.sta.bssid));
        }
        esp_exceptions(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_sta_config));
    }

    esp_exceptions(esp_netif_set_hostname(wlan_sta_obj.netif, mod_network_hostname_data));

    wifi_sta_reconnects = 0;
    // connect to the WiFi AP
    MP_THREAD_GIL_EXIT();
    esp_exceptions(esp_wifi_connect());
    MP_THREAD_GIL_ENTER();
    wifi_sta_connect_requested = true;

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(network_wlan_connect_obj, 1, network_wlan_connect);

static mp_obj_t network_wlan_disconnect(mp_obj_t self_in) {
    wifi_sta_connect_requested = false;
    esp_exceptions(esp_wifi_disconnect());
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_disconnect_obj, network_wlan_disconnect);

static mp_obj_t network_wlan_status(size_t n_args, const mp_obj_t *args) {
    wlan_if_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    if (n_args == 1) {
        if (self->if_id == ESP_IF_WIFI_STA) {
            // Case of no arg is only for the STA interface
            if (wifi_sta_connected) {
                // Happy path, connected with IP
                return MP_OBJ_NEW_SMALL_INT(STAT_GOT_IP);
            } else if (wifi_sta_disconn_reason == WIFI_REASON_NO_AP_FOUND) {
                return MP_OBJ_NEW_SMALL_INT(WIFI_REASON_NO_AP_FOUND);
            #if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0)
            } else if (wifi_sta_disconn_reason == WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD) {
                return MP_OBJ_NEW_SMALL_INT(WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD);
            } else if (wifi_sta_disconn_reason == WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD) {
                return MP_OBJ_NEW_SMALL_INT(WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD);
            } else if (wifi_sta_disconn_reason == WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY) {
                return MP_OBJ_NEW_SMALL_INT(WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY);
            #endif
            } else if ((wifi_sta_disconn_reason == WIFI_REASON_AUTH_FAIL) || (wifi_sta_disconn_reason == WIFI_REASON_CONNECTION_FAIL)) {
                // wrong password
                return MP_OBJ_NEW_SMALL_INT(WIFI_REASON_AUTH_FAIL);
            } else if (wifi_sta_disconn_reason == WIFI_REASON_ASSOC_LEAVE) {
                // After wlan.disconnect()
                return MP_OBJ_NEW_SMALL_INT(STAT_IDLE);
            } else if (wifi_sta_connect_requested
                       && (conf_wifi_sta_reconnects == 0
                           || wifi_sta_reconnects < conf_wifi_sta_reconnects)) {
                // No connection or error, but is requested = Still connecting
                return MP_OBJ_NEW_SMALL_INT(STAT_CONNECTING);
            } else if (wifi_sta_disconn_reason == 0) {
                // No activity, No error = Idle
                return MP_OBJ_NEW_SMALL_INT(STAT_IDLE);
            } else {
                // Simply pass the error through from ESP-identifier
                return MP_OBJ_NEW_SMALL_INT(wifi_sta_disconn_reason);
            }
        }
        return mp_const_none;
    }

    // one argument: return status based on query parameter
    switch ((uintptr_t)args[1]) {
        case (uintptr_t)MP_OBJ_NEW_QSTR(MP_QSTR_stations): {
            // return list of connected stations, only if in soft-AP mode
            require_if(args[0], ESP_IF_WIFI_AP);
            wifi_sta_list_t station_list;
            esp_exceptions(esp_wifi_ap_get_sta_list(&station_list));
            wifi_sta_info_t *stations = (wifi_sta_info_t *)station_list.sta;
            mp_obj_t list = mp_obj_new_list(0, NULL);
            for (int i = 0; i < station_list.num; ++i) {
                mp_obj_tuple_t *t = mp_obj_new_tuple(1, NULL);
                t->items[0] = mp_obj_new_bytes(stations[i].mac, sizeof(stations[i].mac));
                mp_obj_list_append(list, t);
            }
            return list;
        }
        case (uintptr_t)MP_OBJ_NEW_QSTR(MP_QSTR_rssi): {
            // return signal of AP, only in STA mode
            require_if(args[0], ESP_IF_WIFI_STA);

            wifi_ap_record_t info;
            esp_exceptions(esp_wifi_sta_get_ap_info(&info));
            return MP_OBJ_NEW_SMALL_INT(info.rssi);
        }
        default:
            mp_raise_ValueError(MP_ERROR_TEXT("unknown status param"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(network_wlan_status_obj, 1, 2, network_wlan_status);

static mp_obj_t network_wlan_scan(mp_obj_t self_in) {
    // check that STA mode is active
    wifi_mode_t mode;
    esp_exceptions(esp_wifi_get_mode(&mode));
    if ((mode & WIFI_MODE_STA) == 0) {
        mp_raise_msg(&mp_type_OSError, MP_ERROR_TEXT("STA must be active"));
    }

    mp_obj_t list = mp_obj_new_list(0, NULL);
    wifi_scan_config_t config = { 0 };
    config.show_hidden = true;
    MP_THREAD_GIL_EXIT();
    esp_err_t status = esp_wifi_scan_start(&config, 1);
    MP_THREAD_GIL_ENTER();
    if (status == 0) {
        uint16_t count = 0;
        esp_exceptions(esp_wifi_scan_get_ap_num(&count));
        if (count == 0) {
            // esp_wifi_scan_get_ap_records must be called to free internal buffers from the scan.
            // But it returns an error if wifi_ap_records==NULL.  So allocate at least 1 AP entry.
            // esp_wifi_scan_get_ap_records will then return the actual number of APs in count.
            count = 1;
        }
        wifi_ap_record_t *wifi_ap_records = calloc(count, sizeof(wifi_ap_record_t));
        esp_exceptions(esp_wifi_scan_get_ap_records(&count, wifi_ap_records));
        for (uint16_t i = 0; i < count; i++) {
            mp_obj_tuple_t *t = mp_obj_new_tuple(6, NULL);
            uint8_t *x = memchr(wifi_ap_records[i].ssid, 0, sizeof(wifi_ap_records[i].ssid));
            int ssid_len = x ? x - wifi_ap_records[i].ssid : sizeof(wifi_ap_records[i].ssid);
            t->items[0] = mp_obj_new_bytes(wifi_ap_records[i].ssid, ssid_len);
            t->items[1] = mp_obj_new_bytes(wifi_ap_records[i].bssid, sizeof(wifi_ap_records[i].bssid));
            t->items[2] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].primary);
            t->items[3] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].rssi);
            t->items[4] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].authmode);
            t->items[5] = mp_const_false; // XXX hidden?
            mp_obj_list_append(list, MP_OBJ_FROM_PTR(t));
        }
        free(wifi_ap_records);
    }
    return list;
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_scan_obj, network_wlan_scan);

// This is a helper function that handles saving the wifi scan results into the partial scan buffer
static void read_wifi_scan_results(){
    // TODO: Check if the partial_scan_aps exists
    // Create a new list to store the networks
    ESP_LOGI("wifi_blocking_mod", "Getting the number of aps to account for");
    uint16_t count = 0;
    esp_exceptions(esp_wifi_scan_get_ap_num(&count));
    if (count == 0) {
        // esp_wifi_scan_get_ap_records must be called to free internal buffers from the scan.
        // But it returns an error if wifi_ap_records==NULL.  So allocate at least 1 AP entry.
        // esp_wifi_scan_get_ap_records will then return the actual number of APs in count.
        count = 1;
    }
    ESP_LOGI("wifi_blocking_mod", "Allocating the space for %d aps", count);
    wifi_ap_record_t *wifi_ap_records = calloc(count, sizeof(wifi_ap_record_t));
    ESP_LOGI("wifi_blocking_mod", "Getting the records for the aps");
    esp_exceptions(esp_wifi_scan_get_ap_records(&count, wifi_ap_records));
    ESP_LOGI("wifi_blocking_mod", "Starting iterations");
    for (uint16_t i = 0; i < count; i++) {
        // Uncomment all these lines for more verbose of what is going on in here
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying tuple creation", i);
        mp_obj_tuple_t *t = mp_obj_new_tuple(6, NULL);
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying memchr", i);
        uint8_t *x = memchr(wifi_ap_records[i].ssid, 0, sizeof(wifi_ap_records[i].ssid));
        int ssid_len = x ? x - wifi_ap_records[i].ssid : sizeof(wifi_ap_records[i].ssid);
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying ssid_len", i);
        t->items[0] = mp_obj_new_bytes(wifi_ap_records[i].ssid, ssid_len);
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying bssid", i);
        t->items[1] = mp_obj_new_bytes(wifi_ap_records[i].bssid, sizeof(wifi_ap_records[i].bssid));
        t->items[2] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].primary);
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying primary", i);
        t->items[3] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].rssi);
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying authmod", i);
        t->items[4] = MP_OBJ_NEW_SMALL_INT(wifi_ap_records[i].authmode);
        t->items[5] = mp_const_false; // XXX hidden?
        // ESP_LOGE("wifi_blocking_mod", "Iteration %d trying append", i);
        mp_obj_list_append(mp_state_ctx.vm.partial_scan_aps, MP_OBJ_FROM_PTR(t));
    }
    ESP_LOGI("wifi_blocking_mod", "freed the records");
    free(wifi_ap_records);
}

// Get the last results and return them.
/// TODO: Should this return None when there is a scan currently in progress?
/// TODO: Make this a property instead of a function
static mp_obj_t network_wlan_results(mp_obj_t self_in){
    if (mp_state_ctx.vm.last_scan_aps == mp_const_none){
        ESP_LOGI("wifi_blocking_mod", "There has been no scan, therefore the returned value is None");
    } else {
        ESP_LOGI("wifi_blocking_mod", "There has been a scan, which had %ld results", mp_obj_get_int(mp_obj_len(mp_state_ctx.vm.last_scan_aps)));
    }
    return mp_state_ctx.vm.last_scan_aps;
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_results_obj, network_wlan_results);

/// TODO: Make this a property instead of a function
static mp_obj_t network_wlan_in_progress(mp_obj_t self_in){
    return mp_obj_new_bool(scan_in_progress);
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_in_progress_obj, network_wlan_in_progress);

/* Some basic test python code
# This will setup the networking, and also enable the verbose debug logging
import esp; esp.osdebug(esp.LOG_VERBOSE); import network; nic = network.WLAN(network.STA_IF); nic.active(True);

import esp; esp.osdebug(esp.LOG_INFO); import network; nic = network.WLAN(network.STA_IF); nic.active(True);


# Without verbose logging
import network; nic = network.WLAN(network.STA_IF); nic.active(True);

# Single Channel Scan
nic.scan_non_blocking(channel=3)

# Multi channel scan
nic.scan_non_blocking(channel=[2, 3, 9])

# Large min scan time, and print the progress state when done to show it's blocking
nic.scan_non_blocking(channel=3, scan_time_active_min=2000, scan_time_active_max=4000); print(nic.in_progress())

# Same thing, but with non-blocking
nic.scan_non_blocking(channel=3, scan_time_active_min=2000, scan_time_active_max=4000, blocking=False); print(nic.in_progress())

# Scan a couple channels and see the time it takes to when the in_progress changes back to false
def scan_wifi():
    import time
    nic.scan_non_blocking(channel=[2, 3], scan_time_active_min=2000, scan_time_active_max=4000, blocking=False)
    print("We have moved on from that code, and in_progress is: " + str(nic.in_progress()))
    start = time.time_ns()
    while (nic.in_progress()):
        pass
    end = time.time_ns()
    print("Total time: " + str((end - start) / 1000000000.0) + " seconds")

import esp; esp.osdebug(esp.LOG_INFO); import network; nic = network.WLAN(network.STA_IF); nic.active(True);
count = 0
while True:
    print("Iteration: " + str(count))
    nic.scan_non_blocking()
    count = count + 1

# See if the garbage collector is cleaning everything up
def garbage_check():
    import gc
    gc.collect()
    starting_mem = gc.mem_free()
    nic.scan_non_blocking()
    ending_mem = gc.mem_free()
    gc.collect()
    cleaned = gc.mem_free()
    print("starting: " + str(starting_mem) + " ending: " + str(ending_mem) + " cleaned: " + str(cleaned))
    print("overall difference: " + str(starting_mem - cleaned) + " bytes")

# Do it in a loop to try for a memory leak to show up
def garbage_loop(num_loops: int = 100, channel=0):
    import gc
    starting_mem = gc.mem_free()
    for i in range(num_loops):
        loop_start= gc.mem_free()
        nic.scan_non_blocking(channel=channel)
        gc.collect()
        loop_end = gc.mem_free()
        print("Loop interation " + str(i) + " mem changed: " + str(loop_start - loop_end))
    ending_mem = gc.mem_free()
    gc.collect()
    cleaned = gc.mem_free()
    print("starting: " + str(starting_mem) + " ending: " + str(ending_mem) + " cleaned: " + str(cleaned))
    print("overall difference: " + str(starting_mem - cleaned) + " bytes")

Loop testing
>>> micropython.mem_info()
stack: 704 out of 15360
GC: total: 56000, used: 5216, free: 50784, max new split: 102400
 No. of 1-blocks: 64, 2-blocks: 14, max blk sz: 40, max free sz: 3102
>>> garbage_loop(num_loops=1000, channel=[1,2,3,4,5,6,7,8,9,10,11,12,13,14])


Broke?

import network.
self.wlan.scan_non_blocking(blocking=False)
#await uasyncio.sleep_ms(10)
while self.wlan.in_progress():
    await uasyncio.sleep_ms(200)
    continue
nets = self.wlan.results()


import esp;
esp.osdebug(esp.LOG_DEBUG);
import network;
nic = network.WLAN(network.STA_IF);
nic.active(True);
*/

static mp_obj_t network_wlan_non_blocking_scan(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    static const mp_arg_t allowed_args[] = {
        // Create the list of optional elements that can be given, starting with the self object that
        // will always exist 
        { MP_QSTR_self, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_obj = mp_const_none }},
        // If the scan should be sent to the blocking
        { MP_QSTR_blocking, MP_ARG_KW_ONLY | MP_ARG_BOOL, { .u_bool = true }},
        // The channel, or list of channels that should be scanned
        { MP_QSTR_channel, MP_ARG_KW_ONLY | MP_ARG_OBJ, { .u_obj = mp_const_none }},
        // The ssid string that should be scanned for, default of None
        { MP_QSTR_ssid, MP_ARG_KW_ONLY | MP_ARG_OBJ, { .u_obj = mp_const_none }},
        // The mac address bssid that should be scanned for, default is None
        { MP_QSTR_bssid, MP_ARG_KW_ONLY | MP_ARG_OBJ, { .u_obj = mp_const_none }},
        // If hidden networks should be shown, default of false
        { MP_QSTR_show_hidden, MP_ARG_KW_ONLY | MP_ARG_BOOL, { .u_bool = false }},
        // If the scan should be active with WIFI_SCAN_TYPE_ACTIVE
        { MP_QSTR_active_scan, MP_ARG_KW_ONLY | MP_ARG_BOOL, { .u_bool = true }},
        // Time to passive scan, default 360 ms
        { MP_QSTR_scan_time_passive, MP_ARG_KW_ONLY | MP_ARG_INT, { .u_int = 360 }},
        // Min time to spend actively scanning, default of 0 ms
        { MP_QSTR_scan_time_active_min, MP_ARG_KW_ONLY | MP_ARG_INT, { .u_int = 0 }},
        // Max time to spend actively scanning, default of 120 ms
        { MP_QSTR_scan_time_active_max, MP_ARG_KW_ONLY | MP_ARG_INT, { .u_int = 120 }},
        // Time to spend on the home channel between hops if connected to a wifi network to not lose connection, defaults to 30ms
        { MP_QSTR_home_chan_dwell_time, MP_ARG_KW_ONLY | MP_ARG_INT, { .u_int = 30 }},
        // Callback function that will be called with the results from the scan after the non-blocking scan has completed
        { MP_QSTR_callback, MP_ARG_KW_ONLY | MP_ARG_OBJ, { .u_obj = mp_const_none }}
    };

    // Get the args to the function based on the keywords
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    // Raise an error if the scan is already happening
    if (scan_in_progress) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("Scan is already running, cannot start another scan"));
    }

    ESP_LOGE("wifi_blocking_mod", "checking if the remaining lists is an object in scan");
    if(!mp_obj_is_obj(mp_state_ctx.vm.remaining_channels)){
        ESP_LOGE("wifi_blocking_mod", "The remaining_channels was not a real micropython object, recreating a new empty list");
        mp_state_ctx.vm.remaining_channels = mp_obj_new_list(0, NULL);
    } else {
        ESP_LOGE("wifi_blocking_mod", "The remaining_channels was an object?");
        ESP_LOGE("wifi_blocking_mod", "Type %s", mp_obj_get_type_str(mp_state_ctx.vm.remaining_channels));
    }

    // check that STA mode is active
    wifi_mode_t mode;
    esp_exceptions(esp_wifi_get_mode(&mode));
    if ((mode & WIFI_MODE_STA) == 0) {
        mp_raise_msg(&mp_type_OSError, MP_ERROR_TEXT("STA must be active"));
    }

    // Setup some variables
    // Should the scan be blocking
    bool blocking = false;
    /// The channel to scan for a single
    int scan_channel = 0;
    // If there is a list to scan
    bool scan_list = false;

    /// TODO: Check that blocking is valid. I don't think it should ever not be with MP_ARG_BOOL, but unsure
    blocking = args[1].u_bool;

    // Check that the channels are properly typed
    // If the object is an integer, then it's a single channel scan
    if (mp_obj_is_int(args[2].u_obj)){
        int chan = mp_obj_get_int(args[2].u_obj);
        ESP_LOGD("wifi_blocking_mod", "Got a single channel %d", chan);
        if (chan > 14 || chan < 0){
            mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Bad channel value, expecting 1-14"));
        }
        scan_channel = chan;
        /// TODO: Should this force the remaining_channels list to 0 items?
    // Check if the object is a list or tuple
    } else if (mp_obj_is_type(args[2].u_obj, &mp_type_list) || mp_obj_is_type(args[2].u_obj, &mp_type_tuple)){
        ESP_LOGI("wifi_blocking_mod", "Got a list of channels to scan");
        mp_obj_t channel_list = args[2].u_obj;
        int channel_count = mp_obj_get_int(mp_obj_len(channel_list));
        // Check if there are more channels than possible
        if (channel_count > 14) {
            mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("More channels supplied than were possible to scan"));
        // There were no channels given, but there was an array
        } else if(channel_count == 0){
            mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("An array with no channels to scan is invalid"));
        }

        // Get the list of items from the array
        mp_obj_t *items;
        mp_obj_get_array_fixed_n(channel_list, channel_count, &items);
        // Check all the channels themselves for proper values
        for(int i = 0; i < channel_count; i++) {
            // Check that object is an int first
            if (!mp_obj_is_int(items[i])) {
                mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("The channels need to be specified as integers"));
            }
            // Check that it is a valid channel
            int temp_channel_number = mp_obj_get_int(items[i]);
            if (temp_channel_number > 14 || temp_channel_number < 1){
                mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("Unsupported channel values in channel list"));
            }
            // TODO: Check for duplicate channels
        }
        // Set the scan_list flag
        scan_list = true;
        // Set the channel to start this scan on
        scan_channel = mp_obj_get_int(items[0]);
        // Create a new list to use for the channels that need scanned
        // mp_obj_t list = mp_obj_new_list(0, NULL);
        // Start the indexing at 1 since the first channel will be started in this method
        for(int i = 1; i < channel_count; i++){
            ESP_LOGI("wifi_blocking_mod", "Adding channel %ld to the list of channels to scan", mp_obj_get_int(items[i]));
            // Append the channel to the list
            mp_obj_list_append(mp_state_ctx.vm.remaining_channels, items[i]);
        }
        // // Set the remaining channel list to have these saved
        // remaining_channels = list;
    // If there was nothing given assume 0 for scan all
    } else if (args[2].u_obj == mp_const_none) {
        ESP_LOGI("wifi_blocking_mod", "No channels given, scanning all of them");
    } else {
        mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("Channel was invalidly typed"));
    }

    // Check if the ssid exists
    /// TODO: Check that the ssid is valid name for a network
    if (!(args[3].u_obj == mp_const_none) && !mp_obj_is_str(args[3].u_obj)){
        mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("Bad typing on ssid, expected a string"));
    } else {
        ESP_LOGI("wifi_blocking_mod", "There was no ssid");
    }

    // Check if the bssid exists
    /// TODO: Check that the bssid is a valid mac address
    if (!(args[4].u_obj == mp_const_none) && !(mp_obj_is_type(args[4].u_obj, &mp_type_bytes))){
        mp_raise_msg(&mp_type_TypeError, MP_ERROR_TEXT("Bad typing on bssid, expected a string"));
    } else {
        ESP_LOGI("wifi_blocking_mod", "There was no bssid");
    }

    /// TODO: Check that show_hidden is valid
    /// TODO: Check that active_scan is valid
    /// TODO: Check that scan_time_passive is valid
    /// TODO: Check that scan_time_active_max is valid
    /// TODO: Check that scan_time_active_min is valid
    /// TODO: Check that home_dwell_time is valid
    // I think these should always all be valid since they are typed args, but unsure

    /// TODO: Implement having a python callback like this pull request https://github.com/micropython/micropython/pull/7526/files

    // Check if we should blocking, and that a callback exists
    if (args[11].u_obj == mp_const_none && args[1].u_bool) {
        ESP_LOGI("wifi_blocking_mod", "Blocking is true, but there is no callback specified");
    // If there is a callback, but the scan wasn't for the blocking raise an error    
    } else if (args[11].u_obj != mp_const_none && !args[1].u_bool) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("The callback should only be set if a blocking scan is happening"));
    } else if (args[11].u_obj != mp_const_none && mp_obj_is_callable(args[11].u_obj)){
        ESP_LOGI("wifi_blocking_mod", "There is a callback for the blocking scan");
    }

    ESP_LOGI("wifi_blocking_mod", "creating the esp wifi config");
    // Create the temporary null configuration
    wifi_scan_config_t config = { 0 };
    // Copy that null configuration into the global configuration
    memcpy(&scanning_config, &config, sizeof(wifi_scan_config_t));
    // The wifi_scan_config_t has the fields
    // ssid as *uint8
    // bssid as *uint8
    // channel as int for the channel to scan with default of 0 for all
    // show_hidden as boolean for showing hidden networks
    // scan_type as enum, with WIFI_SCAN_TYPE_ACTIVE being the default
    // scan_time which is another struct
    //      scan_time.active.min is the minimum time to spend on a channel looking for APs
    //      scan_time.active.max is the maximum time to spend on a channel looking for APs
    //      scan_time.passive is the time to spend on a channel in a passive scan. Channels 13 and 14 are always passive scans
    // home_chan_dwell_time is the time to jump back to the connected wifi's channel to remain connected

    /// TODO: Read the ssid from the variable and place it into the correct location of the struct

    /// TODO: Take the bssid, and place it into the correct location in the struct
    
    ESP_LOGI("wifi_blocking_mod", "Setting the config channel to %d", scan_channel);
    scanning_config.channel = scan_channel;
    ESP_LOGI("wifi_blocking_mod", "Setting the config show_hidden to %d", args[5].u_bool);
    scanning_config.show_hidden = args[5].u_bool;
    if (args[6].u_bool){
        ESP_LOGD("wifi_blocking_mod", "We are using an active type scan!");
        scanning_config.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    } else {
        ESP_LOGI("wifi_blocking_mod", "We are not using an active scan type");
        scanning_config.scan_type = WIFI_SCAN_TYPE_PASSIVE;
    }
    ESP_LOGI("wifi_blocking_mod", "Setting the config active max to %ld", args[9].u_int);
    scanning_config.scan_time.active.max = args[9].u_int;
    ESP_LOGI("wifi_blocking_mod", "Setting the config active min to %ld", args[8].u_int);
    scanning_config.scan_time.active.min = args[8].u_int;
    ESP_LOGI("wifi_blocking_mod", "Setting the config passive time to %ld", args[7].u_int);
    scanning_config.scan_time.passive = args[7].u_int;
    
    ESP_LOGI("wifi_blocking_mod", "Replacing the current partial_scan_aps with an empty list");
    mp_state_ctx.vm.partial_scan_aps = mp_obj_new_list(0, NULL);

    // Set the scan_in_progress flag
    scan_in_progress = true;
    // Starting the inital scan
    MP_THREAD_GIL_EXIT();
    esp_err_t status = esp_wifi_scan_start(&scanning_config, blocking);
    MP_THREAD_GIL_ENTER();
    esp_exceptions(status);

    // If this is a blocking request wait for the rest scan to complete, and therefore the rest of the channels to complete
    if(blocking) {
        ESP_LOGI("wifi_blocking_mod", "Waiting for scan_in_progress to change to false to unblock");
        if (scan_list){
            ESP_LOGI("wifi_blocking_mod", "There is more than 1 channel to scan, busy waiting for them to finish");
        }
        // Yield our thread in micropython to let another thread run if desired
        // This might not be the same effect as the blocking original, so this might need to be a busy wait?
        while(scan_in_progress){
            mp_event_wait_ms(1);
        }
        ESP_LOGI("wifi_blocking_mod", "scan_in_progress is done!");
        return mp_state_ctx.vm.last_scan_aps;
    // If this is non-blocking, just return None
    } else {
        ESP_LOGI("wifi_blocking_mod", "This should be running in the background, and be non-blocking");
        return mp_const_none;
    }
}
static MP_DEFINE_CONST_FUN_OBJ_KW(network_wlan_scan_non_blocking_obj, 1, network_wlan_non_blocking_scan);

static mp_obj_t network_wlan_isconnected(mp_obj_t self_in) {
    wlan_if_obj_t *self = MP_OBJ_TO_PTR(self_in);
    if (self->if_id == ESP_IF_WIFI_STA) {
        return mp_obj_new_bool(wifi_sta_connected);
    } else {
        wifi_sta_list_t sta;
        esp_wifi_ap_get_sta_list(&sta);
        return mp_obj_new_bool(sta.num != 0);
    }
}
static MP_DEFINE_CONST_FUN_OBJ_1(network_wlan_isconnected_obj, network_wlan_isconnected);

static mp_obj_t network_wlan_config(size_t n_args, const mp_obj_t *args, mp_map_t *kwargs) {
    if (n_args != 1 && kwargs->used != 0) {
        mp_raise_TypeError(MP_ERROR_TEXT("either pos or kw args are allowed"));
    }

    wlan_if_obj_t *self = MP_OBJ_TO_PTR(args[0]);

    bool is_wifi = self->if_id == ESP_IF_WIFI_AP || self->if_id == ESP_IF_WIFI_STA;

    wifi_config_t cfg;
    if (is_wifi) {
        esp_exceptions(esp_wifi_get_config(self->if_id, &cfg));
    }

    if (kwargs->used != 0) {
        if (!is_wifi) {
            goto unknown;
        }

        for (size_t i = 0; i < kwargs->alloc; i++) {
            if (mp_map_slot_is_filled(kwargs, i)) {
                int req_if = -1;

                switch (mp_obj_str_get_qstr(kwargs->table[i].key)) {
                    case MP_QSTR_mac: {
                        mp_buffer_info_t bufinfo;
                        mp_get_buffer_raise(kwargs->table[i].value, &bufinfo, MP_BUFFER_READ);
                        if (bufinfo.len != 6) {
                            mp_raise_ValueError(MP_ERROR_TEXT("invalid buffer length"));
                        }
                        esp_exceptions(esp_wifi_set_mac(self->if_id, bufinfo.buf));
                        break;
                    }
                    case MP_QSTR_ssid:
                    case MP_QSTR_essid: {
                        req_if = ESP_IF_WIFI_AP;
                        size_t len;
                        const char *s = mp_obj_str_get_data(kwargs->table[i].value, &len);
                        len = MIN(len, sizeof(cfg.ap.ssid));
                        memcpy(cfg.ap.ssid, s, len);
                        cfg.ap.ssid_len = len;
                        break;
                    }
                    case MP_QSTR_hidden: {
                        req_if = ESP_IF_WIFI_AP;
                        cfg.ap.ssid_hidden = mp_obj_is_true(kwargs->table[i].value);
                        break;
                    }
                    case MP_QSTR_security:
                    case MP_QSTR_authmode: {
                        req_if = ESP_IF_WIFI_AP;
                        cfg.ap.authmode = mp_obj_get_int(kwargs->table[i].value);
                        break;
                    }
                    case MP_QSTR_key:
                    case MP_QSTR_password: {
                        req_if = ESP_IF_WIFI_AP;
                        size_t len;
                        const char *s = mp_obj_str_get_data(kwargs->table[i].value, &len);
                        len = MIN(len, sizeof(cfg.ap.password) - 1);
                        memcpy(cfg.ap.password, s, len);
                        cfg.ap.password[len] = 0;
                        break;
                    }
                    case MP_QSTR_channel: {
                        uint8_t primary;
                        wifi_second_chan_t secondary;
                        // Get the current value of secondary
                        esp_exceptions(esp_wifi_get_channel(&primary, &secondary));
                        primary = mp_obj_get_int(kwargs->table[i].value);
                        esp_err_t err = esp_wifi_set_channel(primary, secondary);
                        if (err == ESP_ERR_INVALID_ARG) {
                            // May need to swap secondary channel above to below or below to above
                            secondary = (
                                (secondary == WIFI_SECOND_CHAN_ABOVE)
                                ? WIFI_SECOND_CHAN_BELOW
                                : (secondary == WIFI_SECOND_CHAN_BELOW)
                                    ? WIFI_SECOND_CHAN_ABOVE
                                    : WIFI_SECOND_CHAN_NONE);
                            esp_exceptions(esp_wifi_set_channel(primary, secondary));
                        }
                        break;
                    }
                    case MP_QSTR_hostname:
                    case MP_QSTR_dhcp_hostname: {
                        // TODO: Deprecated. Use network.hostname(name) instead.
                        mod_network_hostname(1, &kwargs->table[i].value);
                        break;
                    }
                    case MP_QSTR_max_clients: {
                        req_if = ESP_IF_WIFI_AP;
                        cfg.ap.max_connection = mp_obj_get_int(kwargs->table[i].value);
                        break;
                    }
                    case MP_QSTR_reconnects: {
                        int reconnects = mp_obj_get_int(kwargs->table[i].value);
                        req_if = ESP_IF_WIFI_STA;
                        // parameter reconnects == -1 means to retry forever.
                        // here means conf_wifi_sta_reconnects == 0 to retry forever.
                        conf_wifi_sta_reconnects = (reconnects == -1) ? 0 : reconnects + 1;
                        break;
                    }
                    case MP_QSTR_txpower: {
                        int8_t power = (mp_obj_get_float(kwargs->table[i].value) * 4);
                        esp_exceptions(esp_wifi_set_max_tx_power(power));
                        break;
                    }
                    case MP_QSTR_protocol: {
                        esp_exceptions(esp_wifi_set_protocol(self->if_id, mp_obj_get_int(kwargs->table[i].value)));
                        break;
                    }
                    case MP_QSTR_pm: {
                        esp_exceptions(esp_wifi_set_ps(mp_obj_get_int(kwargs->table[i].value)));
                        break;
                    }
                    default:
                        goto unknown;
                }

                // We post-check interface requirements to save on code size
                if (req_if >= 0) {
                    require_if(args[0], req_if);
                }
            }
        }

        esp_exceptions(esp_wifi_set_config(self->if_id, &cfg));

        return mp_const_none;
    }

    // Get config

    if (n_args != 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("can query only one param"));
    }

    int req_if = -1;
    mp_obj_t val = mp_const_none;

    switch (mp_obj_str_get_qstr(args[1])) {
        case MP_QSTR_mac: {
            uint8_t mac[6];
            switch (self->if_id) {
                case ESP_IF_WIFI_AP: // fallthrough intentional
                case ESP_IF_WIFI_STA:
                    esp_exceptions(esp_wifi_get_mac(self->if_id, mac));
                    return mp_obj_new_bytes(mac, sizeof(mac));
                default:
                    goto unknown;
            }
        }
        case MP_QSTR_ssid:
        case MP_QSTR_essid:
            switch (self->if_id) {
                case ESP_IF_WIFI_STA:
                    val = mp_obj_new_str_from_cstr((char *)cfg.sta.ssid);
                    break;
                case ESP_IF_WIFI_AP:
                    val = mp_obj_new_str((char *)cfg.ap.ssid, cfg.ap.ssid_len);
                    break;
                default:
                    req_if = ESP_IF_WIFI_AP;
            }
            break;
        case MP_QSTR_hidden:
            req_if = ESP_IF_WIFI_AP;
            val = mp_obj_new_bool(cfg.ap.ssid_hidden);
            break;
        case MP_QSTR_security:
        case MP_QSTR_authmode:
            req_if = ESP_IF_WIFI_AP;
            val = MP_OBJ_NEW_SMALL_INT(cfg.ap.authmode);
            break;
        case MP_QSTR_channel: {
            uint8_t channel;
            wifi_second_chan_t second;
            esp_exceptions(esp_wifi_get_channel(&channel, &second));
            val = MP_OBJ_NEW_SMALL_INT(channel);
            break;
        }
        case MP_QSTR_ifname: {
            val = esp_ifname(self->netif);
            break;
        }
        case MP_QSTR_hostname:
        case MP_QSTR_dhcp_hostname: {
            // TODO: Deprecated. Use network.hostname() instead.
            req_if = ESP_IF_WIFI_STA;
            val = mod_network_hostname(0, NULL);
            break;
        }
        case MP_QSTR_max_clients: {
            val = MP_OBJ_NEW_SMALL_INT(cfg.ap.max_connection);
            break;
        }
        case MP_QSTR_reconnects:
            req_if = ESP_IF_WIFI_STA;
            int rec = conf_wifi_sta_reconnects - 1;
            val = MP_OBJ_NEW_SMALL_INT(rec);
            break;
        case MP_QSTR_txpower: {
            int8_t power;
            esp_exceptions(esp_wifi_get_max_tx_power(&power));
            val = mp_obj_new_float(power * 0.25);
            break;
        }
        case MP_QSTR_protocol: {
            uint8_t protocol_bitmap;
            esp_exceptions(esp_wifi_get_protocol(self->if_id, &protocol_bitmap));
            val = MP_OBJ_NEW_SMALL_INT(protocol_bitmap);
            break;
        }
        case MP_QSTR_pm: {
            wifi_ps_type_t ps_type;
            esp_exceptions(esp_wifi_get_ps(&ps_type));
            val = MP_OBJ_NEW_SMALL_INT(ps_type);
            break;
        }
        default:
            goto unknown;
    }

    // We post-check interface requirements to save on code size
    if (req_if >= 0) {
        require_if(args[0], req_if);
    }

    return val;

unknown:
    mp_raise_ValueError(MP_ERROR_TEXT("unknown config param"));
}
MP_DEFINE_CONST_FUN_OBJ_KW(network_wlan_config_obj, 1, network_wlan_config);

static const mp_rom_map_elem_t wlan_if_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_active), MP_ROM_PTR(&network_wlan_active_obj) },
    { MP_ROM_QSTR(MP_QSTR_connect), MP_ROM_PTR(&network_wlan_connect_obj) },
    { MP_ROM_QSTR(MP_QSTR_disconnect), MP_ROM_PTR(&network_wlan_disconnect_obj) },
    { MP_ROM_QSTR(MP_QSTR_status), MP_ROM_PTR(&network_wlan_status_obj) },
    { MP_ROM_QSTR(MP_QSTR_scan), MP_ROM_PTR(&network_wlan_scan_obj) },
    { MP_ROM_QSTR(MP_QSTR_scan_non_blocking), MP_ROM_PTR(&network_wlan_scan_non_blocking_obj) },
    { MP_ROM_QSTR(MP_QSTR_results), MP_ROM_PTR(&network_wlan_results_obj) },
    { MP_ROM_QSTR(MP_QSTR_in_progress), MP_ROM_PTR(&network_wlan_in_progress_obj) },
    { MP_ROM_QSTR(MP_QSTR_isconnected), MP_ROM_PTR(&network_wlan_isconnected_obj) },
    { MP_ROM_QSTR(MP_QSTR_config), MP_ROM_PTR(&network_wlan_config_obj) },
    { MP_ROM_QSTR(MP_QSTR_ifconfig), MP_ROM_PTR(&esp_network_ifconfig_obj) },
    { MP_ROM_QSTR(MP_QSTR_ipconfig), MP_ROM_PTR(&esp_nic_ipconfig_obj) },

    // Constants
    { MP_ROM_QSTR(MP_QSTR_IF_STA), MP_ROM_INT(WIFI_IF_STA)},
    { MP_ROM_QSTR(MP_QSTR_IF_AP), MP_ROM_INT(WIFI_IF_AP)},

    { MP_ROM_QSTR(MP_QSTR_SEC_OPEN), MP_ROM_INT(WIFI_AUTH_OPEN) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WEP), MP_ROM_INT(WIFI_AUTH_WEP) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA), MP_ROM_INT(WIFI_AUTH_WPA_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA2), MP_ROM_INT(WIFI_AUTH_WPA2_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA_WPA2), MP_ROM_INT(WIFI_AUTH_WPA_WPA2_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA2_ENT), MP_ROM_INT(WIFI_AUTH_WPA2_ENTERPRISE) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA3), MP_ROM_INT(WIFI_AUTH_WPA3_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WPA2_WPA3), MP_ROM_INT(WIFI_AUTH_WPA2_WPA3_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_WAPI), MP_ROM_INT(WIFI_AUTH_WAPI_PSK) },
    { MP_ROM_QSTR(MP_QSTR_SEC_OWE), MP_ROM_INT(WIFI_AUTH_OWE) },

    { MP_ROM_QSTR(MP_QSTR_PM_NONE), MP_ROM_INT(WIFI_PS_NONE) },
    { MP_ROM_QSTR(MP_QSTR_PM_PERFORMANCE), MP_ROM_INT(WIFI_PS_MIN_MODEM) },
    { MP_ROM_QSTR(MP_QSTR_PM_POWERSAVE), MP_ROM_INT(WIFI_PS_MAX_MODEM) },
};
static MP_DEFINE_CONST_DICT(wlan_if_locals_dict, wlan_if_locals_dict_table);

MP_DEFINE_CONST_OBJ_TYPE(
    esp_network_wlan_type,
    MP_QSTR_WLAN,
    MP_TYPE_FLAG_NONE,
    make_new, network_wlan_make_new,
    locals_dict, &wlan_if_locals_dict
    );

#endif // MICROPY_PY_NETWORK_WLAN
MP_REGISTER_ROOT_POINTER(mp_obj_t remaining_channels);
MP_REGISTER_ROOT_POINTER(mp_obj_t last_scan_aps);
MP_REGISTER_ROOT_POINTER(mp_obj_t partial_scan_aps);