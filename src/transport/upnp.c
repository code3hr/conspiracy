/**
 * @file upnp.c
 * @brief UPnP IGD and NAT-PMP implementation using miniupnpc
 */

#include "cyxwiz/upnp.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_UPNP

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/time.h>
#endif

/* Internal state structure */
struct cyxwiz_upnp_state {
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lan_addr[64];
    char wan_addr[64];
    uint16_t internal_port;
    uint16_t external_port;
    uint32_t lease_duration;
    uint64_t lease_expiry_ms;
    bool discovered;
    bool mapping_active;
    bool is_natpmp;
};

/* Get current time in milliseconds */
static uint64_t get_time_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

cyxwiz_error_t cyxwiz_upnp_create(cyxwiz_upnp_state_t **state) {
    if (!state) {
        return CYXWIZ_ERR_NULL;
    }

    cyxwiz_upnp_state_t *s = calloc(1, sizeof(cyxwiz_upnp_state_t));
    if (!s) {
        return CYXWIZ_ERR_MEMORY;
    }

    *state = s;
    return CYXWIZ_OK;
}

void cyxwiz_upnp_destroy(cyxwiz_upnp_state_t *state) {
    if (!state) {
        return;
    }

    /* Remove mapping if active */
    if (state->mapping_active) {
        cyxwiz_upnp_remove_mapping(state);
    }

    /* Free UPnP resources */
    if (state->discovered) {
        FreeUPNPUrls(&state->urls);
    }

    free(state);
}

cyxwiz_error_t cyxwiz_upnp_discover(cyxwiz_upnp_state_t *state) {
    if (!state) {
        return CYXWIZ_ERR_NULL;
    }

    int error = 0;
    struct UPNPDev *devlist = NULL;

    /* Discover UPnP devices on the network */
    CYXWIZ_INFO("UPnP: Discovering IGD/NAT-PMP gateway...");

    devlist = upnpDiscover(
        CYXWIZ_UPNP_DISCOVER_TIMEOUT_MS,  /* timeout in ms */
        NULL,                              /* multicast interface (NULL = default) */
        NULL,                              /* minissdpd socket path */
        0,                                 /* local port (0 = any) */
        0,                                 /* IPv6 (0 = IPv4) */
        2,                                 /* TTL */
        &error
    );

    if (!devlist) {
        CYXWIZ_WARN("UPnP: No devices found (error %d)", error);
        return CYXWIZ_ERR_NOT_FOUND;
    }

    /* Find a valid IGD */
    int ret = UPNP_GetValidIGD(
        devlist,
        &state->urls,
        &state->data,
        state->lan_addr,
        sizeof(state->lan_addr)
    );

    freeUPNPDevlist(devlist);

    if (ret == 0) {
        CYXWIZ_WARN("UPnP: No valid IGD found");
        return CYXWIZ_ERR_NOT_FOUND;
    }

    state->discovered = true;

    /* Get external IP address */
    ret = UPNP_GetExternalIPAddress(
        state->urls.controlURL,
        state->data.first.servicetype,
        state->wan_addr
    );

    if (ret != UPNPCOMMAND_SUCCESS) {
        CYXWIZ_WARN("UPnP: Failed to get external IP (error %d)", ret);
        /* Continue anyway - mapping might still work */
    }

    CYXWIZ_INFO("UPnP: Found IGD, LAN=%s, WAN=%s",
                state->lan_addr, state->wan_addr);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_upnp_add_mapping(
    cyxwiz_upnp_state_t *state,
    uint16_t internal_port,
    uint16_t external_port,
    uint32_t lease_seconds
) {
    if (!state) {
        return CYXWIZ_ERR_NULL;
    }

    if (!state->discovered) {
        CYXWIZ_WARN("UPnP: Must discover gateway before adding mapping");
        return CYXWIZ_ERR_INVALID;
    }

    /* Use same port if external_port is 0 */
    if (external_port == 0) {
        external_port = internal_port;
    }

    /* Use default lease if 0 */
    if (lease_seconds == 0) {
        lease_seconds = CYXWIZ_UPNP_DEFAULT_LEASE_SEC;
    }

    char port_str[8];
    char ext_port_str[8];
    char lease_str[16];

    snprintf(port_str, sizeof(port_str), "%u", internal_port);
    snprintf(ext_port_str, sizeof(ext_port_str), "%u", external_port);
    snprintf(lease_str, sizeof(lease_str), "%u", lease_seconds);

    CYXWIZ_INFO("UPnP: Adding port mapping %s:%s -> %s (lease %ss)",
                state->lan_addr, port_str, ext_port_str, lease_str);

    int ret = UPNP_AddPortMapping(
        state->urls.controlURL,
        state->data.first.servicetype,
        ext_port_str,           /* external port */
        port_str,               /* internal port */
        state->lan_addr,        /* internal client */
        "CyxWiz P2P",           /* description */
        "UDP",                  /* protocol */
        NULL,                   /* remote host (NULL = any) */
        lease_str               /* lease duration */
    );

    if (ret != UPNPCOMMAND_SUCCESS) {
        CYXWIZ_WARN("UPnP: Failed to add port mapping (error %d: %s)",
                    ret, strupnperror(ret));
        return CYXWIZ_ERR_NETWORK;
    }

    state->internal_port = internal_port;
    state->external_port = external_port;
    state->lease_duration = lease_seconds;
    state->lease_expiry_ms = get_time_ms() + (uint64_t)lease_seconds * 1000;
    state->mapping_active = true;

    CYXWIZ_INFO("UPnP: Port mapping added successfully, expires in %us", lease_seconds);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_upnp_remove_mapping(cyxwiz_upnp_state_t *state) {
    if (!state) {
        return CYXWIZ_ERR_NULL;
    }

    if (!state->mapping_active) {
        return CYXWIZ_OK;  /* Nothing to remove */
    }

    char ext_port_str[8];
    snprintf(ext_port_str, sizeof(ext_port_str), "%u", state->external_port);

    CYXWIZ_INFO("UPnP: Removing port mapping for port %s", ext_port_str);

    int ret = UPNP_DeletePortMapping(
        state->urls.controlURL,
        state->data.first.servicetype,
        ext_port_str,
        "UDP",
        NULL  /* remote host */
    );

    if (ret != UPNPCOMMAND_SUCCESS) {
        CYXWIZ_WARN("UPnP: Failed to remove port mapping (error %d: %s)",
                    ret, strupnperror(ret));
        /* Continue anyway - mark as inactive */
    } else {
        CYXWIZ_INFO("UPnP: Port mapping removed successfully");
    }

    state->mapping_active = false;
    return CYXWIZ_OK;
}

bool cyxwiz_upnp_needs_renewal(
    cyxwiz_upnp_state_t *state,
    uint64_t now_ms,
    uint64_t threshold_ms
) {
    if (!state || !state->mapping_active) {
        return false;
    }

    if (threshold_ms == 0) {
        threshold_ms = CYXWIZ_UPNP_RENEWAL_THRESHOLD_MS;
    }

    /* Check if lease expires within threshold */
    if (now_ms + threshold_ms >= state->lease_expiry_ms) {
        return true;
    }

    return false;
}

cyxwiz_error_t cyxwiz_upnp_renew(cyxwiz_upnp_state_t *state) {
    if (!state) {
        return CYXWIZ_ERR_NULL;
    }

    if (!state->mapping_active) {
        CYXWIZ_WARN("UPnP: No active mapping to renew");
        return CYXWIZ_ERR_INVALID;
    }

    CYXWIZ_INFO("UPnP: Renewing port mapping lease");

    /* Re-add the mapping with the same parameters */
    return cyxwiz_upnp_add_mapping(
        state,
        state->internal_port,
        state->external_port,
        state->lease_duration
    );
}

cyxwiz_error_t cyxwiz_upnp_get_status(
    cyxwiz_upnp_state_t *state,
    cyxwiz_upnp_status_t *status
) {
    if (!state || !status) {
        return CYXWIZ_ERR_NULL;
    }

    memset(status, 0, sizeof(*status));

    status->discovered = state->discovered;
    status->mapping_active = state->mapping_active;
    status->is_natpmp = state->is_natpmp;

    if (state->discovered) {
        strncpy(status->lan_addr, state->lan_addr, sizeof(status->lan_addr) - 1);
        strncpy(status->wan_addr, state->wan_addr, sizeof(status->wan_addr) - 1);
    }

    if (state->mapping_active) {
        status->internal_port = state->internal_port;
        status->external_port = state->external_port;
        status->lease_duration = state->lease_duration;
        status->lease_expiry_ms = state->lease_expiry_ms;
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_upnp_get_external_ip(
    cyxwiz_upnp_state_t *state,
    char *addr,
    size_t addr_len
) {
    if (!state || !addr || addr_len == 0) {
        return CYXWIZ_ERR_NULL;
    }

    if (!state->discovered) {
        return CYXWIZ_ERR_INVALID;
    }

    strncpy(addr, state->wan_addr, addr_len - 1);
    addr[addr_len - 1] = '\0';

    return CYXWIZ_OK;
}

#endif /* CYXWIZ_HAS_UPNP */
