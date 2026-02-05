/**
 * @file upnp.h
 * @brief UPnP IGD and NAT-PMP port mapping for CyxWiz
 *
 * Provides automatic port forwarding via UPnP Internet Gateway Device (IGD)
 * protocol and Apple's NAT-PMP protocol for improved P2P connectivity.
 *
 * When enabled, UPnP attempts to create a port mapping on the router,
 * allowing direct incoming connections without UDP hole punching delays.
 *
 * Flow:
 *   1. Discover UPnP IGD on local network (or NAT-PMP gateway)
 *   2. Request port mapping (local_port -> external_port)
 *   3. If successful, skip hole punching for incoming connections
 *   4. Periodically renew lease before expiration
 *   5. Remove mapping on shutdown
 */

#ifndef CYXWIZ_UPNP_H
#define CYXWIZ_UPNP_H

#include "cyxwiz/types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CYXWIZ_HAS_UPNP

/**
 * @brief UPnP/NAT-PMP state structure
 *
 * Holds the state for UPnP IGD or NAT-PMP port mapping.
 * This is an opaque structure - use the API functions to interact with it.
 */
typedef struct cyxwiz_upnp_state cyxwiz_upnp_state_t;

/**
 * @brief UPnP status information (for reporting to application)
 */
typedef struct {
    bool discovered;            /**< UPnP IGD or NAT-PMP gateway found */
    bool mapping_active;        /**< Port mapping is active */
    char lan_addr[64];          /**< Local/LAN IP address */
    char wan_addr[64];          /**< External/WAN IP address */
    uint16_t internal_port;     /**< Internal (local) port */
    uint16_t external_port;     /**< External (mapped) port */
    uint32_t lease_duration;    /**< Lease duration in seconds */
    uint64_t lease_expiry_ms;   /**< Absolute time when lease expires (ms) */
    bool is_natpmp;             /**< True if using NAT-PMP, false if UPnP IGD */
} cyxwiz_upnp_status_t;

/**
 * @brief Create UPnP state
 *
 * Allocates and initializes the UPnP state structure.
 *
 * @param[out] state  Pointer to receive the created state
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_create(cyxwiz_upnp_state_t **state);

/**
 * @brief Destroy UPnP state
 *
 * Removes any active port mapping and frees resources.
 *
 * @param state  The UPnP state to destroy
 */
void cyxwiz_upnp_destroy(cyxwiz_upnp_state_t *state);

/**
 * @brief Discover UPnP IGD or NAT-PMP gateway
 *
 * Searches the local network for a UPnP Internet Gateway Device
 * or NAT-PMP compatible router. This is a blocking call that may
 * take several seconds.
 *
 * @param state  The UPnP state
 * @return CYXWIZ_OK if gateway found, CYXWIZ_ERR_NOT_FOUND if no gateway,
 *         or other error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_discover(cyxwiz_upnp_state_t *state);

/**
 * @brief Add port mapping
 *
 * Requests a port mapping from the UPnP IGD or NAT-PMP gateway.
 * Must call cyxwiz_upnp_discover() first.
 *
 * @param state           The UPnP state
 * @param internal_port   Local port to map
 * @param external_port   Requested external port (0 = same as internal)
 * @param lease_seconds   Lease duration in seconds (0 = permanent, not recommended)
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_add_mapping(
    cyxwiz_upnp_state_t *state,
    uint16_t internal_port,
    uint16_t external_port,
    uint32_t lease_seconds
);

/**
 * @brief Remove port mapping
 *
 * Removes the active port mapping from the gateway.
 *
 * @param state  The UPnP state
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_remove_mapping(cyxwiz_upnp_state_t *state);

/**
 * @brief Check if lease needs renewal
 *
 * Returns true if the port mapping lease will expire within the
 * specified threshold (default: 5 minutes before expiry).
 *
 * @param state          The UPnP state
 * @param now_ms         Current time in milliseconds
 * @param threshold_ms   Renewal threshold (0 = use default 300000ms / 5 min)
 * @return true if renewal needed, false otherwise
 */
bool cyxwiz_upnp_needs_renewal(
    cyxwiz_upnp_state_t *state,
    uint64_t now_ms,
    uint64_t threshold_ms
);

/**
 * @brief Renew port mapping lease
 *
 * Extends the lease duration of the current port mapping.
 *
 * @param state  The UPnP state
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_renew(cyxwiz_upnp_state_t *state);

/**
 * @brief Get UPnP status
 *
 * Retrieves the current status of UPnP/NAT-PMP including
 * addresses, ports, and lease information.
 *
 * @param state   The UPnP state
 * @param status  Pointer to receive the status
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_get_status(
    cyxwiz_upnp_state_t *state,
    cyxwiz_upnp_status_t *status
);

/**
 * @brief Get external (WAN) IP address
 *
 * Returns the external IP address discovered via UPnP/NAT-PMP.
 * Must call cyxwiz_upnp_discover() first.
 *
 * @param state     The UPnP state
 * @param[out] addr Buffer to receive the IP address string (at least 64 bytes)
 * @param addr_len  Size of the buffer
 * @return CYXWIZ_OK on success, error code on failure
 */
cyxwiz_error_t cyxwiz_upnp_get_external_ip(
    cyxwiz_upnp_state_t *state,
    char *addr,
    size_t addr_len
);

#endif /* CYXWIZ_HAS_UPNP */

/* Default constants */
#define CYXWIZ_UPNP_DEFAULT_LEASE_SEC     3600    /**< Default lease: 1 hour */
#define CYXWIZ_UPNP_RENEWAL_THRESHOLD_MS  300000  /**< Renew 5 min before expiry */
#define CYXWIZ_UPNP_DISCOVER_TIMEOUT_MS   2000    /**< Discovery timeout: 2 sec */

#ifdef __cplusplus
}
#endif

#endif /* CYXWIZ_UPNP_H */
