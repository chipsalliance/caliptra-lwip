/**
 * @file
 *
 * DHCPv6 client: IPv6 address autoconfiguration as per
 * RFC 3315 (stateful DHCPv6) and
 * RFC 3736 (stateless DHCPv6).
 */

/*
 * Copyright (c) 2018 Simon Goldschmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 */

#ifndef LWIP_HDR_IP6_DHCP6_H
#define LWIP_HDR_IP6_DHCP6_H

#include "lwip/opt.h"

#if LWIP_IPV6_DHCP6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/err.h"
#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/** period (in milliseconds) of the application calling dhcp6_tmr() */
#define DHCP6_TIMER_MSECS   500

struct dhcp6
{
  /** transaction identifier of last sent request */
  u32_t xid;
  /** track PCB allocation state */
  u8_t pcb_allocated;
  /** current DHCPv6 state machine state */
  u8_t state;
  /** retries of current request */
  u8_t tries;
  /** if request config is triggered while another action is active, this keeps track of it */
  u8_t request_config_pending;
  /** #ticks with period DHCP6_TIMER_MSECS for request timeout */
  u16_t request_timeout;
#if LWIP_IPV6_DHCP6_STATEFUL
  /** Client DUID (DUID-LL: type(2) + hwtype(2) + hwaddr(NETIF_MAX_HWADDR_LEN)) */
  u8_t duid[4 + NETIF_MAX_HWADDR_LEN];
  u8_t duid_len;
  /** Server DUID received in ADVERTISE */
  u8_t server_duid[128];
  u16_t server_duid_len;
  /** Server preference from ADVERTISE */
  u8_t server_pref;
  /** IA_NA Identity Association ID */
  u32_t ia_id;
  /** Assigned IPv6 address from IA_NA */
  ip6_addr_t ia_addr;
  /** Lifetimes from IAADDR (seconds) */
  u32_t preferred_lifetime;
  u32_t valid_lifetime;
  /** T1/T2 from IA_NA (seconds) */
  u32_t t1;
  u32_t t2;
  /** Lease timers in DHCP6_TIMER_MSECS ticks */
  u32_t t1_timeout;
  u32_t t2_timeout;
  u32_t lease_timeout;
  /** Retransmission timeout in msecs (RFC 8415 §15) */
  u32_t rt_msecs;
  /** Elapsed time since start of current exchange in msecs */
  u32_t elapsed_msecs;
  /** Index of assigned address in netif, -1 if none */
  s8_t addr_idx;
  /** Boot file URL from Option 59 (RFC 5970), e.g. "tftp://[fd00::1]/boot.bin" */
  char boot_file_url[128];
  u8_t boot_file_url_len;
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
};

void dhcp6_set_struct(struct netif *netif, struct dhcp6 *dhcp6);
/** Remove a struct dhcp6 previously set to the netif using dhcp6_set_struct() */
#define dhcp6_remove_struct(netif) netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL)
void dhcp6_cleanup(struct netif *netif);

err_t dhcp6_enable_stateful(struct netif *netif);
err_t dhcp6_enable_stateless(struct netif *netif);
void dhcp6_disable(struct netif *netif);

void dhcp6_tmr(void);

void dhcp6_nd6_ra_trigger(struct netif *netif, u8_t managed_addr_config, u8_t other_config);

#if LWIP_DHCP6_GET_NTP_SRV
/** This function must exist, in other to add offered NTP servers to
 * the NTP (or SNTP) engine.
 * See LWIP_DHCP6_MAX_NTP_SERVERS */
extern void dhcp6_set_ntp_servers(u8_t num_ntp_servers, const ip_addr_t* ntp_server_addrs);
#endif /* LWIP_DHCP6_GET_NTP_SRV */

#define netif_dhcp6_data(netif) ((struct dhcp6*)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6))

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV6_DHCP6 */

#endif /* LWIP_HDR_IP6_DHCP6_H */
