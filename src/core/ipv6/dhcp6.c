/**
 * @file
 *
 * @defgroup dhcp6 DHCPv6
 * @ingroup ip6
 * DHCPv6 client: IPv6 address autoconfiguration as per
 * RFC 3315 (stateful DHCPv6) and
 * RFC 3736 (stateless DHCPv6).
 *
 * For now, only stateless DHCPv6 is implemented!
 *
 * TODO:
 * - enable/disable API to not always start when RA is received
 * - stateful DHCPv6 (for now, only stateless DHCPv6 for DNS and NTP servers works)
 * - create Client Identifier?
 * - only start requests if a valid local address is available on the netif
 * - only start information requests if required (not for every RA)
 *
 * dhcp6_enable_stateful() enables stateful DHCPv6 for a netif (stateless disabled)<br>
 * dhcp6_enable_stateless() enables stateless DHCPv6 for a netif (stateful disabled)<br>
 * dhcp6_disable() disable DHCPv6 for a netif
 *
 * When enabled, requests are only issued after receipt of RA with the
 * corresponding bits set.
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

#include "lwip/opt.h"

#if LWIP_IPV6 && LWIP_IPV6_DHCP6 /* don't build if not configured for use in lwipopts.h */

#include "lwip/dhcp6.h"
#include "lwip/prot/dhcp6.h"
#include "lwip/def.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/prot/ip6.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif
#ifndef LWIP_HOOK_DHCP6_APPEND_OPTIONS
#define LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, state, msg, msg_type, options_len_ptr, max_len)
#endif
#ifndef LWIP_HOOK_DHCP6_PARSE_OPTION
#define LWIP_HOOK_DHCP6_PARSE_OPTION(netif, dhcp6, state, msg, msg_type, option, len, pbuf, offset) do { LWIP_UNUSED_ARG(msg); } while(0)
#endif

#if LWIP_DNS && LWIP_DHCP6_MAX_DNS_SERVERS
#if DNS_MAX_SERVERS > LWIP_DHCP6_MAX_DNS_SERVERS
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS LWIP_DHCP6_MAX_DNS_SERVERS
#else
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS DNS_MAX_SERVERS
#endif
#else
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS 0
#endif


/** Option handling: options are parsed in dhcp6_parse_reply
 * and saved in an array where other functions can load them from.
 * This might be moved into the struct dhcp6 (not necessarily since
 * lwIP is single-threaded and the array is only used while in recv
 * callback). */
enum dhcp6_option_idx {
  DHCP6_OPTION_IDX_CLI_ID = 0,
  DHCP6_OPTION_IDX_SERVER_ID,
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
  DHCP6_OPTION_IDX_DNS_SERVER,
  DHCP6_OPTION_IDX_DOMAIN_LIST,
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS */
#if LWIP_DHCP6_GET_NTP_SRV
  DHCP6_OPTION_IDX_NTP_SERVER,
#endif /* LWIP_DHCP_GET_NTP_SRV */
#if LWIP_IPV6_DHCP6_STATEFUL
  DHCP6_OPTION_IDX_IA_NA,
  DHCP6_OPTION_IDX_STATUS_CODE,
  DHCP6_OPTION_IDX_PREFERENCE,
  DHCP6_OPTION_IDX_BOOTFILE_URL,
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
  DHCP6_OPTION_IDX_MAX
};

struct dhcp6_option_info {
  u8_t option_given;
  u16_t val_start;
  u16_t val_length;
};

/** Holds the decoded option info, only valid while in dhcp6_recv. */
struct dhcp6_option_info dhcp6_rx_options[DHCP6_OPTION_IDX_MAX];

#define dhcp6_option_given(dhcp6, idx)           (dhcp6_rx_options[idx].option_given != 0)
#define dhcp6_got_option(dhcp6, idx)             (dhcp6_rx_options[idx].option_given = 1)
#define dhcp6_clear_option(dhcp6, idx)           (dhcp6_rx_options[idx].option_given = 0)
#define dhcp6_clear_all_options(dhcp6)           (memset(dhcp6_rx_options, 0, sizeof(dhcp6_rx_options)))
#define dhcp6_get_option_start(dhcp6, idx)       (dhcp6_rx_options[idx].val_start)
#define dhcp6_get_option_length(dhcp6, idx)      (dhcp6_rx_options[idx].val_length)
#define dhcp6_set_option(dhcp6, idx, start, len) do { dhcp6_rx_options[idx].val_start = (start); dhcp6_rx_options[idx].val_length = (len); }while(0)


const ip_addr_t dhcp6_All_DHCP6_Relay_Agents_and_Servers = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0x00010002);
const ip_addr_t dhcp6_All_DHCP6_Servers = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0x00010003);

static struct udp_pcb *dhcp6_pcb;
static u8_t dhcp6_pcb_refcount;


/* receive, unfold, parse and free incoming messages */
static void dhcp6_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

/** Ensure DHCP PCB is allocated and bound */
static err_t
dhcp6_inc_pcb_refcount(void)
{
  if (dhcp6_pcb_refcount == 0) {
    LWIP_ASSERT("dhcp6_inc_pcb_refcount(): memory leak", dhcp6_pcb == NULL);

    /* allocate UDP PCB */
    dhcp6_pcb = udp_new_ip6();

    if (dhcp6_pcb == NULL) {
      return ERR_MEM;
    }

    ip_set_option(dhcp6_pcb, SOF_BROADCAST);

    /* set up local and remote port for the pcb -> listen on all interfaces on all src/dest IPs */
    udp_bind(dhcp6_pcb, IP6_ADDR_ANY, DHCP6_CLIENT_PORT);
    udp_recv(dhcp6_pcb, dhcp6_recv, NULL);
  }

  dhcp6_pcb_refcount++;

  return ERR_OK;
}

/** Free DHCP PCB if the last netif stops using it */
static void
dhcp6_dec_pcb_refcount(void)
{
  LWIP_ASSERT("dhcp6_pcb_refcount(): refcount error", (dhcp6_pcb_refcount > 0));
  dhcp6_pcb_refcount--;

  if (dhcp6_pcb_refcount == 0) {
    udp_remove(dhcp6_pcb);
    dhcp6_pcb = NULL;
  }
}

/**
 * @ingroup dhcp6
 * Set a statically allocated struct dhcp6 to work with.
 * Using this prevents dhcp6_start to allocate it using mem_malloc.
 *
 * @param netif the netif for which to set the struct dhcp
 * @param dhcp6 (uninitialised) dhcp6 struct allocated by the application
 */
void
dhcp6_set_struct(struct netif *netif, struct dhcp6 *dhcp6)
{
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("dhcp6 != NULL", dhcp6 != NULL);
  LWIP_ASSERT("netif already has a struct dhcp6 set", netif_dhcp6_data(netif) == NULL);

  /* clear data structure */
  memset(dhcp6, 0, sizeof(struct dhcp6));
  /* dhcp6_set_state(&dhcp, DHCP6_STATE_OFF); */
  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, dhcp6);
}

/**
 * @ingroup dhcp6
 * Removes a struct dhcp6 from a netif.
 *
 * ATTENTION: Only use this when not using dhcp6_set_struct() to allocate the
 *            struct dhcp6 since the memory is passed back to the heap.
 *
 * @param netif the netif from which to remove the struct dhcp
 */
void dhcp6_cleanup(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", netif != NULL);

  if (netif_dhcp6_data(netif) != NULL) {
    mem_free(netif_dhcp6_data(netif));
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL);
  }
}

static struct dhcp6*
dhcp6_get_struct(struct netif *netif, const char *dbg_requester)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  if (dhcp6 == NULL) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: mallocing new DHCPv6 client\n", dbg_requester));
    dhcp6 = (struct dhcp6 *)mem_malloc(sizeof(struct dhcp6));
    if (dhcp6 == NULL) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: could not allocate dhcp6\n", dbg_requester));
      return NULL;
    }

    /* clear data structure, this implies DHCP6_STATE_OFF */
    memset(dhcp6, 0, sizeof(struct dhcp6));
    /* store this dhcp6 client in the netif */
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, dhcp6);
  } else {
    /* already has DHCP6 client attached */
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("%s: using existing DHCPv6 client\n", dbg_requester));
  }

  if (!dhcp6->pcb_allocated) {
    if (dhcp6_inc_pcb_refcount() != ERR_OK) { /* ensure DHCP6 PCB is allocated */
      mem_free(dhcp6);
      netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL);
      return NULL;
    }
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: allocated dhcp6\n", dbg_requester));
    dhcp6->pcb_allocated = 1;
  }
  return dhcp6;
}

/*
 * Set the DHCPv6 state
 * If the state changed, reset the number of tries.
 */
static void
dhcp6_set_state(struct dhcp6 *dhcp6, u8_t new_state, const char *dbg_caller)
{
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("DHCPv6 state: %d -> %d (%s)\n",
    dhcp6->state, new_state, dbg_caller));
  if (new_state != dhcp6->state) {
    dhcp6->state = new_state;
    dhcp6->tries = 0;
    dhcp6->request_timeout = 0;
  }
}

static int
dhcp6_stateless_enabled(struct dhcp6 *dhcp6)
{
  if ((dhcp6->state == DHCP6_STATE_STATELESS_IDLE) ||
      (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG)) {
    return 1;
  }
  return 0;
}

/*static int
dhcp6_stateful_enabled(struct dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_OFF) {
    return 0;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    return 0;
  }
  return 1;
}*/

#if LWIP_IPV6_DHCP6_STATEFUL
static int
dhcp6_stateful_enabled(struct dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_OFF) {
    return 0;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    return 0;
  }
  return 1;
}
#endif /* LWIP_IPV6_DHCP6_STATEFUL */

/**
 * @ingroup dhcp6
 * Enable stateful DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_MANAGED_ADDR_CONFIG flag set.
 *
 * A struct dhcp6 will be allocated for this netif if not
 * set via @ref dhcp6_set_struct before.
 */
err_t
dhcp6_enable_stateful(struct netif *netif)
{
#if LWIP_IPV6_DHCP6_STATEFUL
  struct dhcp6 *dhcp6;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
    ("dhcp6_enable_stateful(netif=%p) %c%c%"U16_F"\n",
     (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  dhcp6 = dhcp6_get_struct(netif, "dhcp6_enable_stateful()");
  if (dhcp6 == NULL) {
    return ERR_MEM;
  }
  if (dhcp6_stateful_enabled(dhcp6)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
      ("dhcp6_enable_stateful(): stateful DHCPv6 already enabled\n"));
    return ERR_OK;
  } else if (dhcp6_stateless_enabled(dhcp6)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
      ("dhcp6_enable_stateful(): switching from stateless to stateful DHCPv6\n"));
  }

  /* Generate DUID-LL from netif hardware address */
  dhcp6->duid[0] = 0;
  dhcp6->duid[1] = (u8_t)DHCP6_DUID_LL;  /* DUID type = Link-layer */
  dhcp6->duid[2] = 0;
  dhcp6->duid[3] = 1;                      /* Hardware type = Ethernet */
  SMEMCPY(&dhcp6->duid[4], netif->hwaddr, netif->hwaddr_len);
  dhcp6->duid_len = (u8_t)(4 + netif->hwaddr_len);

  /* Use a deterministic IA_ID derived from hardware address */
  dhcp6->ia_id = (u32_t)(netif->hwaddr[netif->hwaddr_len - 4]) << 24 |
                 (u32_t)(netif->hwaddr[netif->hwaddr_len - 3]) << 16 |
                 (u32_t)(netif->hwaddr[netif->hwaddr_len - 2]) << 8  |
                 (u32_t)(netif->hwaddr[netif->hwaddr_len - 1]);
  dhcp6->addr_idx = -1;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
    ("dhcp6_enable_stateful(): stateful DHCPv6 enabled\n"));
  dhcp6_set_state(dhcp6, DHCP6_STATE_STATEFUL_IDLE, "dhcp6_enable_stateful");
  return ERR_OK;
#else
  LWIP_UNUSED_ARG(netif);
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
    ("stateful dhcp6 not enabled in build config\n"));
  return ERR_VAL;
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
}

/**
 * @ingroup dhcp6
 * Enable stateless DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_OTHER_CONFIG flag set.
 *
 * A struct dhcp6 will be allocated for this netif if not
 * set via @ref dhcp6_set_struct before.
 */
err_t
dhcp6_enable_stateless(struct netif *netif)
{
  struct dhcp6 *dhcp6;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_enable_stateless(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  dhcp6 = dhcp6_get_struct(netif, "dhcp6_enable_stateless()");
  if (dhcp6 == NULL) {
    return ERR_MEM;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): stateless DHCPv6 already enabled\n"));
    return ERR_OK;
  } else if (dhcp6->state != DHCP6_STATE_OFF) {
    /* stateful running */
    /* @todo: stop stateful once it is implemented */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): switching from stateful to stateless DHCPv6\n"));
  }
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): stateless DHCPv6 enabled\n"));
  dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_enable_stateless");
  return ERR_OK;
}

/**
 * @ingroup dhcp6
 * Disable stateful or stateless DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_OTHER_CONFIG flag set.
 */
void
dhcp6_disable(struct netif *netif)
{
  struct dhcp6 *dhcp6;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_disable(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  dhcp6 = netif_dhcp6_data(netif);
  if (dhcp6 != NULL) {
    if (dhcp6->state != DHCP6_STATE_OFF) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_disable(): DHCPv6 disabled (old state: %s)\n",
        (dhcp6_stateless_enabled(dhcp6) ? "stateless" : "stateful")));
#if LWIP_IPV6_DHCP6_STATEFUL
      /* Remove assigned address if we had one */
      if (dhcp6->addr_idx >= 0) {
        netif_ip6_addr_set_state(netif, dhcp6->addr_idx, IP6_ADDR_INVALID);
        dhcp6->addr_idx = -1;
      }
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
      dhcp6_set_state(dhcp6, DHCP6_STATE_OFF, "dhcp6_disable");
      if (dhcp6->pcb_allocated != 0) {
        dhcp6_dec_pcb_refcount(); /* free DHCPv6 PCB if not needed any more */
        dhcp6->pcb_allocated = 0;
      }
    }
  }
}

/**
 * Create a DHCPv6 request, fill in common headers
 *
 * @param netif the netif under DHCPv6 control
 * @param dhcp6 dhcp6 control struct
 * @param message_type message type of the request
 * @param opt_len_alloc option length to allocate
 * @param options_out_len option length on exit
 * @return a pbuf for the message
 */
static struct pbuf *
dhcp6_create_msg(struct netif *netif, struct dhcp6 *dhcp6, u8_t message_type,
                 u16_t opt_len_alloc, u16_t *options_out_len)
{
  struct pbuf *p_out;
  struct dhcp6_msg *msg_out;

  LWIP_ERROR("dhcp6_create_msg: netif != NULL", (netif != NULL), return NULL;);
  LWIP_ERROR("dhcp6_create_msg: dhcp6 != NULL", (dhcp6 != NULL), return NULL;);
  p_out = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcp6_msg) + opt_len_alloc, PBUF_RAM);
  if (p_out == NULL) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp6_create_msg(): could not allocate pbuf\n"));
    return NULL;
  }
  LWIP_ASSERT("dhcp6_create_msg: check that first pbuf can hold struct dhcp6_msg",
              (p_out->len >= sizeof(struct dhcp6_msg) + opt_len_alloc));

  /* @todo: limit new xid for certain message types? */
  /* reuse transaction identifier in retransmissions */
  if (dhcp6->tries == 0) {
    dhcp6->xid = LWIP_RAND() & 0xFFFFFF;
  }

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
              ("transaction id xid(%"X32_F")\n", dhcp6->xid));

  msg_out = (struct dhcp6_msg *)p_out->payload;
  memset(msg_out, 0, sizeof(struct dhcp6_msg) + opt_len_alloc);

  msg_out->msgtype = message_type;
  msg_out->transaction_id[0] = (u8_t)(dhcp6->xid >> 16);
  msg_out->transaction_id[1] = (u8_t)(dhcp6->xid >> 8);
  msg_out->transaction_id[2] = (u8_t)dhcp6->xid;
  *options_out_len = 0;
  return p_out;
}

static u16_t
dhcp6_option_short(u16_t options_out_len, u8_t *options, u16_t value)
{
  options[options_out_len++] = (u8_t)((value & 0xff00U) >> 8);
  options[options_out_len++] = (u8_t) (value & 0x00ffU);
  return options_out_len;
}

static u16_t
dhcp6_option_optionrequest(u16_t options_out_len, u8_t *options, const u16_t *req_options,
                           u16_t num_req_options, u16_t max_len)
{
  size_t i;
  u16_t ret;

  LWIP_ASSERT("dhcp6_option_optionrequest: options_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + options_out_len + 4U + (2U * num_req_options) <= max_len);
  LWIP_UNUSED_ARG(max_len);

  ret = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_ORO);
  ret = dhcp6_option_short(ret, options, 2 * num_req_options);
  for (i = 0; i < num_req_options; i++) {
    ret = dhcp6_option_short(ret, options, req_options[i]);
  }
  return ret;
}

/* All options are added, shrink the pbuf to the required size */
static void
dhcp6_msg_finalize(u16_t options_out_len, struct pbuf *p_out)
{
  /* shrink the pbuf to the actual content length */
  pbuf_realloc(p_out, (u16_t)(sizeof(struct dhcp6_msg) + options_out_len));
}

static u16_t
dhcp6_option_long(u16_t options_out_len, u8_t *options, u32_t value)
{
  options[options_out_len++] = (u8_t)((value >> 24) & 0xffU);
  options[options_out_len++] = (u8_t)((value >> 16) & 0xffU);
  options[options_out_len++] = (u8_t)((value >>  8) & 0xffU);
  options[options_out_len++] = (u8_t)(value & 0xffU);
  return options_out_len;
}

#if LWIP_IPV6_DHCP6_STATEFUL

/* Retransmission parameters from RFC 8415 */
#define DHCP6_SOL_MAX_DELAY_MS   1000
#define DHCP6_SOL_TIMEOUT_MS     1000
#define DHCP6_SOL_MAX_RT_MS      3600000
#define DHCP6_REQ_TIMEOUT_MS     1000
#define DHCP6_REQ_MAX_RT_MS      30000
#define DHCP6_REQ_MAX_RC         10
#define DHCP6_REN_TIMEOUT_MS     10000
#define DHCP6_REN_MAX_RT_MS      600000
#define DHCP6_REB_TIMEOUT_MS     10000
#define DHCP6_REB_MAX_RT_MS      600000

/* Maximum option space we allocate for stateful messages */
#define DHCP6_STATEFUL_OPTIONS_LEN  256

/** Append Client Identifier option (DUID-LL) */
static u16_t
dhcp6_option_clientid(u16_t options_out_len, u8_t *options, struct dhcp6 *dhcp6)
{
  u8_t i;
  options_out_len = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_CLIENTID);
  options_out_len = dhcp6_option_short(options_out_len, options, dhcp6->duid_len);
  for (i = 0; i < dhcp6->duid_len; i++) {
    options[options_out_len++] = dhcp6->duid[i];
  }
  return options_out_len;
}

/** Append Server Identifier option (copy of server's DUID) */
static u16_t
dhcp6_option_serverid(u16_t options_out_len, u8_t *options, struct dhcp6 *dhcp6)
{
  u16_t i;
  options_out_len = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_SERVERID);
  options_out_len = dhcp6_option_short(options_out_len, options, dhcp6->server_duid_len);
  for (i = 0; i < dhcp6->server_duid_len; i++) {
    options[options_out_len++] = dhcp6->server_duid[i];
  }
  return options_out_len;
}

/** Append Elapsed Time option */
static u16_t
dhcp6_option_elapsed_time(u16_t options_out_len, u8_t *options, struct dhcp6 *dhcp6)
{
  u16_t elapsed_csecs;
  /* elapsed time in centiseconds, capped at 0xFFFF */
  if (dhcp6->elapsed_msecs / 10 > 0xFFFF) {
    elapsed_csecs = 0xFFFF;
  } else {
    elapsed_csecs = (u16_t)(dhcp6->elapsed_msecs / 10);
  }
  options_out_len = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_ELAPSED_TIME);
  options_out_len = dhcp6_option_short(options_out_len, options, 2); /* length = 2 */
  options_out_len = dhcp6_option_short(options_out_len, options, elapsed_csecs);
  return options_out_len;
}

/** Append IA_NA option (with empty IA Address sub-option for SOLICIT/REQUEST) */
static u16_t
dhcp6_option_ia_na(u16_t options_out_len, u8_t *options, struct dhcp6 *dhcp6)
{
  options_out_len = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_IA_NA);
  options_out_len = dhcp6_option_short(options_out_len, options, 12); /* IAID(4) + T1(4) + T2(4) */
  options_out_len = dhcp6_option_long(options_out_len, options, dhcp6->ia_id);
  options_out_len = dhcp6_option_long(options_out_len, options, 0); /* T1 = 0 (let server decide) */
  options_out_len = dhcp6_option_long(options_out_len, options, 0); /* T2 = 0 (let server decide) */
  return options_out_len;
}

/**
 * Calculate the next retransmission timeout per RFC 8415 §15.
 * RT = 2*RTprev + RAND*RTprev, clamped to MRT.
 * First transmission: RT = IRT + RAND*IRT.
 */
static u32_t
dhcp6_calc_retransmit_timeout(struct dhcp6 *dhcp6, u32_t irt_ms, u32_t mrt_ms)
{
  u32_t rt;
  /* RAND is a random number between -0.1 and +0.1 of the value.
   * We approximate with (LWIP_RAND() % 200 - 100) / 1000 factor. */
  s32_t rand_factor = (s32_t)(LWIP_RAND() % 201) - 100; /* -100 to +100 */

  if (dhcp6->tries == 0) {
    /* First retransmission */
    rt = irt_ms + (u32_t)((s32_t)irt_ms * rand_factor / 1000);
  } else {
    u32_t prev_rt = dhcp6->rt_msecs;
    rt = 2 * prev_rt + (u32_t)((s32_t)prev_rt * rand_factor / 1000);
  }

  if (mrt_ms != 0 && rt > mrt_ms) {
    rt = mrt_ms + (u32_t)((s32_t)mrt_ms * rand_factor / 1000);
  }

  /* Ensure minimum of 1 timer tick */
  if (rt < DHCP6_TIMER_MSECS) {
    rt = DHCP6_TIMER_MSECS;
  }

  dhcp6->rt_msecs = rt;
  return rt;
}

/** Send a DHCPv6 SOLICIT message to begin address acquisition */
static void
dhcp6_solicit(struct netif *netif, struct dhcp6 *dhcp6)
{
  const u16_t requested_options[] = {
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
    DHCP6_OPTION_DNS_SERVERS,
    DHCP6_OPTION_DOMAIN_LIST,
#endif
#if LWIP_DHCP6_GET_NTP_SRV
    DHCP6_OPTION_SNTP_SERVERS,
#endif
    DHCP6_OPTION_BOOTFILE_URL,
  };
  struct pbuf *p_out;
  u16_t options_out_len;
  u32_t rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_solicit()\n"));

  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_SOLICIT,
    DHCP6_STATEFUL_OPTIONS_LEN, &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);

    options_out_len = dhcp6_option_clientid(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_elapsed_time(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_ia_na(options_out_len, options, dhcp6);
    if (LWIP_ARRAYSIZE(requested_options) > 0) {
      options_out_len = dhcp6_option_optionrequest(options_out_len, options,
        requested_options, LWIP_ARRAYSIZE(requested_options), p_out->len);
    }

    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_SOLICITING, msg_out,
      DHCP6_SOLICIT, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
      ("dhcp6_solicit: SOLICITING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
      ("dhcp6_solicit: could not allocate DHCP6 request\n"));
  }

  dhcp6_set_state(dhcp6, DHCP6_STATE_SOLICITING, "dhcp6_solicit");
  rt = dhcp6_calc_retransmit_timeout(dhcp6, DHCP6_SOL_TIMEOUT_MS, DHCP6_SOL_MAX_RT_MS);
  dhcp6->request_timeout = (u16_t)((rt + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6->elapsed_msecs += rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
    ("dhcp6_solicit(): set request timeout %"U32_F" msecs (try %"U16_F")\n",
     rt, (u16_t)dhcp6->tries));
}

/** Send a DHCPv6 REQUEST message after selecting a server from ADVERTISE */
static void
dhcp6_stateful_request(struct netif *netif, struct dhcp6 *dhcp6)
{
  const u16_t requested_options[] = {
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
    DHCP6_OPTION_DNS_SERVERS,
    DHCP6_OPTION_DOMAIN_LIST,
#endif
#if LWIP_DHCP6_GET_NTP_SRV
    DHCP6_OPTION_SNTP_SERVERS,
#endif
    DHCP6_OPTION_BOOTFILE_URL,
  };
  struct pbuf *p_out;
  u16_t options_out_len;
  u32_t rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_stateful_request()\n"));

  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_REQUEST,
    DHCP6_STATEFUL_OPTIONS_LEN, &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);

    options_out_len = dhcp6_option_clientid(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_serverid(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_elapsed_time(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_ia_na(options_out_len, options, dhcp6);
    if (LWIP_ARRAYSIZE(requested_options) > 0) {
      options_out_len = dhcp6_option_optionrequest(options_out_len, options,
        requested_options, LWIP_ARRAYSIZE(requested_options), p_out->len);
    }

    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_REQUESTING, msg_out,
      DHCP6_REQUEST, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
      ("dhcp6_stateful_request: REQUESTING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
      ("dhcp6_stateful_request: could not allocate DHCP6 request\n"));
  }

  dhcp6_set_state(dhcp6, DHCP6_STATE_REQUESTING, "dhcp6_stateful_request");
  rt = dhcp6_calc_retransmit_timeout(dhcp6, DHCP6_REQ_TIMEOUT_MS, DHCP6_REQ_MAX_RT_MS);
  dhcp6->request_timeout = (u16_t)((rt + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6->elapsed_msecs += rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
    ("dhcp6_stateful_request(): set request timeout %"U32_F" msecs (try %"U16_F")\n",
     rt, (u16_t)dhcp6->tries));
}

/** Send a DHCPv6 RENEW message to extend the lease */
static void
dhcp6_renew(struct netif *netif, struct dhcp6 *dhcp6)
{
  struct pbuf *p_out;
  u16_t options_out_len;
  u32_t rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_renew()\n"));

  /* Reset retransmission state for RENEW exchange */
  dhcp6->tries = 0;
  dhcp6->elapsed_msecs = 0;

  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_RENEW,
    DHCP6_STATEFUL_OPTIONS_LEN, &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);

    options_out_len = dhcp6_option_clientid(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_serverid(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_elapsed_time(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_ia_na(options_out_len, options, dhcp6);

    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_RENEWING, msg_out,
      DHCP6_RENEW, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
      ("dhcp6_renew: RENEWING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  }

  dhcp6_set_state(dhcp6, DHCP6_STATE_RENEWING, "dhcp6_renew");
  rt = dhcp6_calc_retransmit_timeout(dhcp6, DHCP6_REN_TIMEOUT_MS, DHCP6_REN_MAX_RT_MS);
  dhcp6->request_timeout = (u16_t)((rt + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6->elapsed_msecs += rt;
}

/** Send a DHCPv6 REBIND message (multicast, any server) */
static void
dhcp6_rebind(struct netif *netif, struct dhcp6 *dhcp6)
{
  struct pbuf *p_out;
  u16_t options_out_len;
  u32_t rt;

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_rebind()\n"));

  /* Reset retransmission state for REBIND exchange */
  dhcp6->tries = 0;
  dhcp6->elapsed_msecs = 0;

  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_REBIND,
    DHCP6_STATEFUL_OPTIONS_LEN, &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);

    options_out_len = dhcp6_option_clientid(options_out_len, options, dhcp6);
    /* No Server ID in REBIND per RFC 8415 */
    options_out_len = dhcp6_option_elapsed_time(options_out_len, options, dhcp6);
    options_out_len = dhcp6_option_ia_na(options_out_len, options, dhcp6);

    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_REBINDING, msg_out,
      DHCP6_REBIND, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
      ("dhcp6_rebind: REBINDING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  }

  dhcp6_set_state(dhcp6, DHCP6_STATE_REBINDING, "dhcp6_rebind");
  rt = dhcp6_calc_retransmit_timeout(dhcp6, DHCP6_REB_TIMEOUT_MS, DHCP6_REB_MAX_RT_MS);
  dhcp6->request_timeout = (u16_t)((rt + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6->elapsed_msecs += rt;
}

/**
 * Parse IA_NA sub-options (IAADDR, STATUS_CODE) from a received IA_NA option.
 * @return ERR_OK if a valid address was found, ERR_VAL otherwise
 */
static err_t
dhcp6_parse_ia_na_options(struct pbuf *p, u16_t ia_offset, u16_t ia_len, struct dhcp6 *dhcp6)
{
  u16_t offset;
  u16_t offset_max;
  u8_t found_addr = 0;

  /* IA_NA contains: IAID(4) + T1(4) + T2(4) = 12 bytes fixed, then sub-options */
  if (ia_len < 12) {
    return ERR_VAL;
  }

  /* Read T1 and T2 from IA_NA */
  {
    u8_t buf[4];
    u8_t *data;
    u32_t iaid;

    data = (u8_t *)pbuf_get_contiguous(p, buf, 4, 4, ia_offset);
    if (data == NULL) return ERR_BUF;
    iaid = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
           ((u32_t)data[2] << 8)  | (u32_t)data[3];
    if (iaid != dhcp6->ia_id) {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: IA_ID mismatch: got %"X32_F" expected %"X32_F"\n",
        iaid, dhcp6->ia_id));
      return ERR_VAL;
    }

    data = (u8_t *)pbuf_get_contiguous(p, buf, 4, 4, (u16_t)(ia_offset + 4));
    if (data == NULL) return ERR_BUF;
    dhcp6->t1 = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
                ((u32_t)data[2] << 8)  | (u32_t)data[3];

    data = (u8_t *)pbuf_get_contiguous(p, buf, 4, 4, (u16_t)(ia_offset + 8));
    if (data == NULL) return ERR_BUF;
    dhcp6->t2 = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
                ((u32_t)data[2] << 8)  | (u32_t)data[3];
  }

  offset = (u16_t)(ia_offset + 12);
  offset_max = (u16_t)(ia_offset + ia_len);

  while (offset + 4 <= offset_max) {
    u8_t op_buf[4];
    u8_t *op_data;
    u16_t sub_op, sub_len;
    u16_t sub_val_offset;

    op_data = (u8_t *)pbuf_get_contiguous(p, op_buf, 4, 4, offset);
    if (op_data == NULL) break;

    sub_op  = (u16_t)((op_data[0] << 8) | op_data[1]);
    sub_len = (u16_t)((op_data[2] << 8) | op_data[3]);
    sub_val_offset = (u16_t)(offset + 4);

    if (sub_val_offset + sub_len > offset_max) break;

    if (sub_op == DHCP6_OPTION_IAADDR && sub_len >= 24 && !found_addr) {
      /* IAADDR: IPv6 address(16) + preferred_lifetime(4) + valid_lifetime(4) */
      u8_t addr_buf[16];
      u8_t lt_buf[4];
      u8_t *lt_data;
      u16_t copied;

      copied = pbuf_copy_partial(p, addr_buf, 16, sub_val_offset);
      if (copied != 16) break;

      ip6_addr_copy_from_packed(dhcp6->ia_addr, *((const ip6_addr_p_t *)addr_buf));

      lt_data = (u8_t *)pbuf_get_contiguous(p, lt_buf, 4, 4, (u16_t)(sub_val_offset + 16));
      if (lt_data == NULL) break;
      dhcp6->preferred_lifetime = ((u32_t)lt_data[0] << 24) | ((u32_t)lt_data[1] << 16) |
                                  ((u32_t)lt_data[2] << 8)  | (u32_t)lt_data[3];

      lt_data = (u8_t *)pbuf_get_contiguous(p, lt_buf, 4, 4, (u16_t)(sub_val_offset + 20));
      if (lt_data == NULL) break;
      dhcp6->valid_lifetime = ((u32_t)lt_data[0] << 24) | ((u32_t)lt_data[1] << 16) |
                              ((u32_t)lt_data[2] << 8)  | (u32_t)lt_data[3];

      found_addr = 1;
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
        ("dhcp6: got IA_ADDR preferred=%"U32_F" valid=%"U32_F"\n",
         dhcp6->preferred_lifetime, dhcp6->valid_lifetime));
    } else if (sub_op == DHCP6_OPTION_STATUS_CODE && sub_len >= 2) {
      u8_t sc_buf[2];
      u8_t *sc_data;
      u16_t status;

      sc_data = (u8_t *)pbuf_get_contiguous(p, sc_buf, 2, 2, sub_val_offset);
      if (sc_data == NULL) break;
      status = (u16_t)((sc_data[0] << 8) | sc_data[1]);
      if (status != DHCP6_STATUS_SUCCESS) {
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6: IA status code = %"U16_F"\n", status));
        return ERR_VAL;
      }
    }

    offset = (u16_t)(sub_val_offset + sub_len);
  }

  return found_addr ? ERR_OK : ERR_VAL;
}

/**
 * Handle an ADVERTISE message received while in SOLICITING state.
 * Saves server DUID and preference. If preference == 255, immediately
 * transitions to REQUEST; otherwise waits for the current retransmit
 * timeout to collect more advertisements.
 */
static void
dhcp6_handle_advertise(struct netif *netif, struct pbuf *p)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);

  if (dhcp6->state != DHCP6_STATE_SOLICITING) {
    return;
  }

  /* Must have both Client ID and Server ID */
  if (!dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_CLI_ID) ||
      !dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_SERVER_ID)) {
    LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: ADVERTISE missing Client/Server ID\n"));
    return;
  }

  /* Verify Client ID matches our DUID */
  {
    u16_t cli_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
    u16_t cli_len   = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
    u8_t cli_buf[20]; /* enough for DUID-LL */
    u16_t copied;

    if (cli_len != dhcp6->duid_len || cli_len > sizeof(cli_buf)) {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: ADVERTISE client ID length mismatch\n"));
      return;
    }
    copied = pbuf_copy_partial(p, cli_buf, cli_len, cli_start);
    if (copied != cli_len || memcmp(cli_buf, dhcp6->duid, cli_len) != 0) {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: ADVERTISE client ID mismatch\n"));
      return;
    }
  }

  /* Check top-level status code if present */
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE)) {
    u16_t sc_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
    u8_t sc_buf[2];
    u8_t *sc_data;
    u16_t status;

    sc_data = (u8_t *)pbuf_get_contiguous(p, sc_buf, 2, 2, sc_start);
    if (sc_data != NULL) {
      status = (u16_t)((sc_data[0] << 8) | sc_data[1]);
      if (status != DHCP6_STATUS_SUCCESS) {
        LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: ADVERTISE status code = %"U16_F"\n", status));
        return;
      }
    }
  }

  /* Get the preference value */
  {
    u8_t pref = 0;
    if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_PREFERENCE)) {
      u16_t pref_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_PREFERENCE);
      u8_t pref_buf[1];
      u8_t *pref_data;
      pref_data = (u8_t *)pbuf_get_contiguous(p, pref_buf, 1, 1, pref_start);
      if (pref_data != NULL) {
        pref = pref_data[0];
      }
    }

    /* Accept this server if we haven't saved one yet or this has higher preference */
    if (dhcp6->server_duid_len == 0 || pref > dhcp6->server_pref) {
      u16_t srv_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
      u16_t srv_len   = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);

      if (srv_len <= sizeof(dhcp6->server_duid)) {
        u16_t copied = pbuf_copy_partial(p, dhcp6->server_duid, srv_len, srv_start);
        if (copied == srv_len) {
          dhcp6->server_duid_len = srv_len;
          dhcp6->server_pref = pref;
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
            ("dhcp6: saved server DUID (len=%"U16_F", pref=%"U16_F")\n",
             srv_len, (u16_t)pref));
        }
      }
    }

    /* If preference is 255, go to REQUEST immediately (RFC 8415 §18.2.1) */
    if (pref == 255 && dhcp6->server_duid_len > 0) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
        ("dhcp6: ADVERTISE pref=255, sending REQUEST immediately\n"));
      dhcp6->tries = 0;
      dhcp6->elapsed_msecs = 0;
      dhcp6_stateful_request(netif, dhcp6);
    }
    /* Otherwise, current timeout expiry in dhcp6_timeout will trigger REQUEST
     * if we have a server_duid saved. */
  }
}

/**
 * Handle a REPLY message to a stateful REQUEST/RENEW/REBIND.
 * Extracts IA_NA address and installs it on the netif.
 */
static void
dhcp6_handle_stateful_reply(struct netif *netif, struct pbuf *p)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);

  /* Must have Server ID */
  if (!dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_SERVER_ID)) {
    LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: REPLY missing Server ID\n"));
    return;
  }

  /* Verify Client ID matches */
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_CLI_ID)) {
    u16_t cli_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
    u16_t cli_len   = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
    u8_t cli_buf[20];

    if (cli_len != dhcp6->duid_len || cli_len > sizeof(cli_buf)) {
      return;
    }
    if (pbuf_copy_partial(p, cli_buf, cli_len, cli_start) != cli_len) {
      return;
    }
    if (memcmp(cli_buf, dhcp6->duid, cli_len) != 0) {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: REPLY client ID mismatch\n"));
      return;
    }
  }

  /* Check top-level status code */
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE)) {
    u16_t sc_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
    u8_t sc_buf[2];
    u8_t *sc_data;
    u16_t status;

    sc_data = (u8_t *)pbuf_get_contiguous(p, sc_buf, 2, 2, sc_start);
    if (sc_data != NULL) {
      status = (u16_t)((sc_data[0] << 8) | sc_data[1]);
      if (status != DHCP6_STATUS_SUCCESS) {
        LWIP_DEBUGF(DHCP6_DEBUG,
          ("dhcp6: REPLY status code = %"U16_F", restarting SOLICIT\n", status));
        /* On failure, restart discovery */
        dhcp6->server_duid_len = 0;
        dhcp6->tries = 0;
        dhcp6->elapsed_msecs = 0;
        dhcp6_solicit(netif, dhcp6);
        return;
      }
    }
  }

  /* Parse IA_NA option to extract address and lifetimes */
  if (!dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_IA_NA)) {
    LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: REPLY missing IA_NA\n"));
    /* If in REQUEST state with no IA, restart */
    if (dhcp6->state == DHCP6_STATE_REQUESTING) {
      dhcp6->server_duid_len = 0;
      dhcp6->tries = 0;
      dhcp6->elapsed_msecs = 0;
      dhcp6_solicit(netif, dhcp6);
    }
    return;
  }

  {
    u16_t ia_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_IA_NA);
    u16_t ia_len   = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_IA_NA);

    if (dhcp6_parse_ia_na_options(p, ia_start, ia_len, dhcp6) != ERR_OK) {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: REPLY IA_NA parse failed\n"));
      if (dhcp6->state == DHCP6_STATE_REQUESTING) {
        dhcp6->server_duid_len = 0;
        dhcp6->tries = 0;
        dhcp6->elapsed_msecs = 0;
        dhcp6_solicit(netif, dhcp6);
      }
      return;
    }
  }

  /* Success — install address on netif */
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
    ("dhcp6: REPLY accepted, binding address T1=%"U32_F" T2=%"U32_F
     " preferred=%"U32_F" valid=%"U32_F"\n",
     dhcp6->t1, dhcp6->t2, dhcp6->preferred_lifetime, dhcp6->valid_lifetime));

  /* Find or reuse an address slot */
  if (dhcp6->addr_idx < 0) {
    s8_t i;
    s8_t free_idx = -1;
    /* Look for an existing slot with same address or a free slot (skip slot 0 = link-local) */
    for (i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
      if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, i))) {
        if (free_idx < 0) {
          free_idx = i;
        }
      } else if (ip6_addr_cmp(&dhcp6->ia_addr, netif_ip6_addr(netif, i))) {
        free_idx = i;
        break;
      }
    }
    if (free_idx < 0) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("dhcp6: no free address slot on netif\n"));
      return;
    }
    dhcp6->addr_idx = free_idx;
  }

  ip6_addr_assign_zone(&dhcp6->ia_addr, IP6_UNICAST, netif);
  netif_ip6_addr_set(netif, dhcp6->addr_idx, &dhcp6->ia_addr);
  netif_ip6_addr_set_valid_life(netif, dhcp6->addr_idx, dhcp6->valid_lifetime);
  netif_ip6_addr_set_pref_life(netif, dhcp6->addr_idx, dhcp6->preferred_lifetime);
  netif_ip6_addr_set_state(netif, dhcp6->addr_idx, IP6_ADDR_TENTATIVE);

  /* Set lease timers (in units of DHCP6_TIMER_MSECS ticks) */
  /* T1/T2 of 0 means server lets client choose; use 0.5/0.8 of preferred lifetime */
  if (dhcp6->t1 == 0 && dhcp6->preferred_lifetime != 0xFFFFFFFFUL) {
    dhcp6->t1 = dhcp6->preferred_lifetime / 2;
  }
  if (dhcp6->t2 == 0 && dhcp6->preferred_lifetime != 0xFFFFFFFFUL) {
    dhcp6->t2 = (dhcp6->preferred_lifetime * 4) / 5;
  }

  /* Convert seconds to timer ticks (protect against overflow) */
  if (dhcp6->t1 != 0xFFFFFFFFUL && dhcp6->t1 != 0) {
    dhcp6->t1_timeout = dhcp6->t1 * (1000 / DHCP6_TIMER_MSECS);
  } else {
    dhcp6->t1_timeout = 0; /* infinite or zero = no renewal */
  }
  if (dhcp6->t2 != 0xFFFFFFFFUL && dhcp6->t2 != 0) {
    dhcp6->t2_timeout = dhcp6->t2 * (1000 / DHCP6_TIMER_MSECS);
  } else {
    dhcp6->t2_timeout = 0;
  }
  if (dhcp6->valid_lifetime != 0xFFFFFFFFUL) {
    dhcp6->lease_timeout = dhcp6->valid_lifetime * (1000 / DHCP6_TIMER_MSECS);
  } else {
    dhcp6->lease_timeout = 0;
  }

  dhcp6_set_state(dhcp6, DHCP6_STATE_BOUND, "dhcp6_handle_stateful_reply");

  /* Extract Boot File URL (Option 59, RFC 5970) if present */
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_BOOTFILE_URL)) {
    u16_t bf_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_BOOTFILE_URL);
    u16_t bf_len   = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_BOOTFILE_URL);
    u16_t copy_len = bf_len;

    if (copy_len > sizeof(dhcp6->boot_file_url) - 1) {
      copy_len = sizeof(dhcp6->boot_file_url) - 1;
    }
    if (pbuf_copy_partial(p, dhcp6->boot_file_url, copy_len, bf_start) == copy_len) {
      dhcp6->boot_file_url[copy_len] = '\0';
      dhcp6->boot_file_url_len = (u8_t)copy_len;
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
        ("dhcp6: Boot File URL: %s\n", dhcp6->boot_file_url));
    } else {
      dhcp6->boot_file_url[0] = '\0';
      dhcp6->boot_file_url_len = 0;
    }
  }

  /* Also process DNS/NTP options if present (reuse stateless handler) */
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER)) {
    ip_addr_t dns_addr;
    ip6_addr_t *dns_addr6;
    u16_t op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t idx;
    u8_t n;
    ip_addr_set_zero_ip6(&dns_addr);
    dns_addr6 = ip_2_ip6(&dns_addr);
    for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_PROVIDE_DNS_SERVERS);
         n++, idx += sizeof(struct ip6_addr_packed)) {
      u16_t copied = pbuf_copy_partial(p, dns_addr6, sizeof(struct ip6_addr_packed), idx);
      if (copied != sizeof(struct ip6_addr_packed)) break;
      ip6_addr_assign_zone(dns_addr6, IP6_UNKNOWN, netif);
      dns_setserver(n, &dns_addr);
    }
  }
#endif /* LWIP_DHCP6_PROVIDE_DNS_SERVERS */
}

#endif /* LWIP_IPV6_DHCP6_STATEFUL */


#if LWIP_IPV6_DHCP6_STATELESS
static void
dhcp6_information_request(struct netif *netif, struct dhcp6 *dhcp6)
{
  const u16_t requested_options[] = {
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
    DHCP6_OPTION_DNS_SERVERS,
    DHCP6_OPTION_DOMAIN_LIST
#endif
#if LWIP_DHCP6_GET_NTP_SRV
    , DHCP6_OPTION_SNTP_SERVERS
#endif
  };

  u16_t msecs;
  struct pbuf *p_out;
  u16_t options_out_len;
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_information_request()\n"));
  /* create and initialize the DHCP message header */
  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_INFOREQUEST, 4 + sizeof(requested_options), &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_information_request: making request\n"));

    options_out_len = dhcp6_option_optionrequest(options_out_len, options, requested_options,
      LWIP_ARRAYSIZE(requested_options), p_out->len);
    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_REQUESTING_CONFIG, msg_out,
      DHCP6_INFOREQUEST, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers, DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_information_request: INFOREQUESTING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp6_information_request: could not allocate DHCP6 request\n"));
  }
  dhcp6_set_state(dhcp6, DHCP6_STATE_REQUESTING_CONFIG, "dhcp6_information_request");
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  msecs = (u16_t)((dhcp6->tries < 6 ? 1 << dhcp6->tries : 60) * 1000);
  dhcp6->request_timeout = (u16_t)((msecs + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_information_request(): set request timeout %"U16_F" msecs\n", msecs));
}

static err_t
dhcp6_request_config(struct netif *netif, struct dhcp6 *dhcp6)
{
  /* stateless mode enabled and no request running? */
  if (dhcp6->state == DHCP6_STATE_STATELESS_IDLE) {
    /* send Information-request and wait for answer; setup receive timeout */
    dhcp6_information_request(netif, dhcp6);
  }

  return ERR_OK;
}

static void
dhcp6_abort_config_request(struct dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    /* abort running request */
    dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_abort_config_request");
  }
}

/* Handle a REPLY to INFOREQUEST
 * This parses DNS and NTP server addresses from the reply.
 */
static void
dhcp6_handle_config_reply(struct netif *netif, struct pbuf *p_msg_in)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);

  LWIP_UNUSED_ARG(dhcp6);
  LWIP_UNUSED_ARG(p_msg_in);

#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER)) {
    ip_addr_t dns_addr;
    ip6_addr_t *dns_addr6;
    u16_t op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t idx;
    u8_t n;

    ip_addr_set_zero_ip6(&dns_addr);
    dns_addr6 = ip_2_ip6(&dns_addr);
    for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_PROVIDE_DNS_SERVERS);
         n++, idx += sizeof(struct ip6_addr_packed)) {
      u16_t copied = pbuf_copy_partial(p_msg_in, dns_addr6, sizeof(struct ip6_addr_packed), idx);
      if (copied != sizeof(struct ip6_addr_packed)) {
        /* pbuf length mismatch */
        return;
      }
      ip6_addr_assign_zone(dns_addr6, IP6_UNKNOWN, netif);
      /* @todo: do we need a different offset than DHCP(v4)? */
      dns_setserver(n, &dns_addr);
    }
  }
  /* @ todo: parse and set Domain Search List */
#endif /* LWIP_DHCP6_PROVIDE_DNS_SERVERS */

#if LWIP_DHCP6_GET_NTP_SRV
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER)) {
    ip_addr_t ntp_server_addrs[LWIP_DHCP6_MAX_NTP_SERVERS];
    u16_t op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
    u16_t op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
    u16_t idx;
    u8_t n;

    for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_MAX_NTP_SERVERS);
         n++, idx += sizeof(struct ip6_addr_packed)) {
      u16_t copied;
      ip6_addr_t *ntp_addr6 = ip_2_ip6(&ntp_server_addrs[n]);
      ip_addr_set_zero_ip6(&ntp_server_addrs[n]);
      copied = pbuf_copy_partial(p_msg_in, ntp_addr6, sizeof(struct ip6_addr_packed), idx);
      if (copied != sizeof(struct ip6_addr_packed)) {
        /* pbuf length mismatch */
        return;
      }
      ip6_addr_assign_zone(ntp_addr6, IP6_UNKNOWN, netif);
    }
    dhcp6_set_ntp_servers(n, ntp_server_addrs);
  }
#endif /* LWIP_DHCP6_GET_NTP_SRV */
}
#endif /* LWIP_IPV6_DHCP6_STATELESS */

/** This function is called from nd6 module when an RA message is received
 * It triggers DHCPv6 requests (if enabled).
 */
void
dhcp6_nd6_ra_trigger(struct netif *netif, u8_t managed_addr_config, u8_t other_config)
{
  struct dhcp6 *dhcp6;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  dhcp6 = netif_dhcp6_data(netif);

  LWIP_UNUSED_ARG(managed_addr_config);
  LWIP_UNUSED_ARG(other_config);
  LWIP_UNUSED_ARG(dhcp6);

#if LWIP_IPV6_DHCP6_STATEFUL
  if (dhcp6 != NULL) {
    if (dhcp6->state == DHCP6_STATE_STATEFUL_IDLE && managed_addr_config) {
      /* RA has M flag set — begin SOLICIT */
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
        ("dhcp6_nd6_ra_trigger: M flag set, starting SOLICIT\n"));
      dhcp6->server_duid_len = 0;
      dhcp6->tries = 0;
      dhcp6->elapsed_msecs = 0;
      dhcp6_solicit(netif, dhcp6);
    }
  }
#endif /* LWIP_IPV6_DHCP6_STATEFUL */

#if LWIP_IPV6_DHCP6_STATELESS
  if (dhcp6 != NULL) {
    if (dhcp6_stateless_enabled(dhcp6)) {
      if (other_config) {
        dhcp6_request_config(netif, dhcp6);
      } else {
        dhcp6_abort_config_request(dhcp6);
      }
    }
  }
#endif /* LWIP_IPV6_DHCP6_STATELESS */
}

/**
 * Parse the DHCPv6 message and extract the DHCPv6 options.
 *
 * Extract the DHCPv6 options (offset + length) so that we can later easily
 * check for them or extract the contents.
 */
static err_t
dhcp6_parse_reply(struct pbuf *p, struct dhcp6 *dhcp6)
{
  u16_t offset;
  u16_t offset_max;
  u16_t options_idx;
  struct dhcp6_msg *msg_in;

  LWIP_UNUSED_ARG(dhcp6);

  /* clear received options */
  dhcp6_clear_all_options(dhcp6);
  msg_in = (struct dhcp6_msg *)p->payload;

  /* parse options */

  options_idx = sizeof(struct dhcp6_msg);
  /* parse options to the end of the received packet */
  offset_max = p->tot_len;

  offset = options_idx;
  /* at least 4 byte to read? */
  while ((offset + 4 <= offset_max)) {
    u8_t op_len_buf[4];
    u8_t *op_len;
    u16_t op;
    u16_t len;
    u16_t val_offset = (u16_t)(offset + 4);
    if (val_offset < offset) {
      /* overflow */
      return ERR_BUF;
    }
    /* copy option + length, might be split across pbufs */
    op_len = (u8_t *)pbuf_get_contiguous(p, op_len_buf, 4, 4, offset);
    if (op_len == NULL) {
      /* failed to get option and length */
      return ERR_VAL;
    }
    op = (op_len[0] << 8) | op_len[1];
    len = (op_len[2] << 8) | op_len[3];
    offset = val_offset + len;
    if (offset < val_offset) {
      /* overflow */
      return ERR_BUF;
    }

    switch (op) {
      case (DHCP6_OPTION_CLIENTID):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID, val_offset, len);
        break;
      case (DHCP6_OPTION_SERVERID):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID, val_offset, len);
        break;
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
      case (DHCP6_OPTION_DNS_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER, val_offset, len);
        break;
      case (DHCP6_OPTION_DOMAIN_LIST):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST, val_offset, len);
        break;
#endif /* LWIP_DHCP6_PROVIDE_DNS_SERVERS */
#if LWIP_DHCP6_GET_NTP_SRV
      case (DHCP6_OPTION_SNTP_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER, val_offset, len);
        break;
#endif /* LWIP_DHCP6_GET_NTP_SRV*/
#if LWIP_IPV6_DHCP6_STATEFUL
      case (DHCP6_OPTION_IA_NA):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_IA_NA);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_IA_NA, val_offset, len);
        break;
      case (DHCP6_OPTION_STATUS_CODE):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE, val_offset, len);
        break;
      case (DHCP6_OPTION_PREFERENCE):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_PREFERENCE);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_PREFERENCE, val_offset, len);
        break;
      case (DHCP6_OPTION_BOOTFILE_URL):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_BOOTFILE_URL);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_BOOTFILE_URL, val_offset, len);
        break;
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
      default:
        LWIP_DEBUGF(DHCP6_DEBUG, ("skipping option %"U16_F" in options\n", op));
        LWIP_HOOK_DHCP6_PARSE_OPTION(ip_current_netif(), dhcp6, dhcp6->state, msg_in,
          msg_in->msgtype, op, len, q, val_offset);
        break;
    }
  }
  return ERR_OK;
}

static void
dhcp6_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  struct netif *netif = ip_current_input_netif();
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  struct dhcp6_msg *reply_msg = (struct dhcp6_msg *)p->payload;
  u8_t msg_type;
  u32_t xid;

  LWIP_UNUSED_ARG(arg);

  /* Caught DHCPv6 message from netif that does not have DHCPv6 enabled? -> not interested */
  if ((dhcp6 == NULL) || (dhcp6->pcb_allocated == 0)) {
    goto free_pbuf_and_return;
  }

  LWIP_ERROR("invalid server address type", IP_IS_V6(addr), goto free_pbuf_and_return;);

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_recv(pbuf = %p) from DHCPv6 server %s port %"U16_F"\n", (void *)p,
    ipaddr_ntoa(addr), port));
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("pbuf->len = %"U16_F"\n", p->len));
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("pbuf->tot_len = %"U16_F"\n", p->tot_len));
  /* prevent warnings about unused arguments */
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(addr);
  LWIP_UNUSED_ARG(port);

  if (p->len < sizeof(struct dhcp6_msg)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("DHCPv6 reply message or pbuf too short\n"));
    goto free_pbuf_and_return;
  }

  /* match transaction ID against what we expected */
  xid = reply_msg->transaction_id[0] << 16;
  xid |= reply_msg->transaction_id[1] << 8;
  xid |= reply_msg->transaction_id[2];
  if (xid != dhcp6->xid) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("transaction id mismatch reply_msg->xid(%"X32_F")!= dhcp6->xid(%"X32_F")\n", xid, dhcp6->xid));
    goto free_pbuf_and_return;
  }
  /* option fields could be unfold? */
  if (dhcp6_parse_reply(p, dhcp6) != ERR_OK) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("problem unfolding DHCPv6 message - too short on memory?\n"));
    goto free_pbuf_and_return;
  }

  /* read DHCP message type */
  msg_type = reply_msg->msgtype;

#if LWIP_IPV6_DHCP6_STATEFUL
  /* Handle ADVERTISE in response to SOLICIT */
  if (msg_type == DHCP6_ADVERTISE) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("DHCP6_ADVERTISE received\n"));
    dhcp6_handle_advertise(netif, p);
    goto free_pbuf_and_return;
  }
#endif /* LWIP_IPV6_DHCP6_STATEFUL */

  /* message type is DHCP6 REPLY? */
  if (msg_type == DHCP6_REPLY) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("DHCP6_REPLY received\n"));
#if LWIP_IPV6_DHCP6_STATEFUL
    /* Handle REPLY for stateful REQUEST/RENEW/REBIND */
    if (dhcp6->state == DHCP6_STATE_REQUESTING ||
        dhcp6->state == DHCP6_STATE_RENEWING ||
        dhcp6->state == DHCP6_STATE_REBINDING) {
      dhcp6_handle_stateful_reply(netif, p);
    } else
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
#if LWIP_IPV6_DHCP6_STATELESS
    /* in info-requesting state? */
    if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
      dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_recv");
      dhcp6_handle_config_reply(netif, p);
    } else
#endif /* LWIP_IPV6_DHCP6_STATELESS */
    {
      LWIP_DEBUGF(DHCP6_DEBUG, ("dhcp6: REPLY in unexpected state %d\n", dhcp6->state));
    }
  }

free_pbuf_and_return:
  pbuf_free(p);
}

/**
 * A DHCPv6 request has timed out.
 *
 * The timer that was started with the DHCPv6 request has
 * timed out, indicating no response was received in time.
 */
static void
dhcp6_timeout(struct netif *netif, struct dhcp6 *dhcp6)
{
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout()\n"));

  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(dhcp6);

#if LWIP_IPV6_DHCP6_STATEFUL
  switch (dhcp6->state) {
    case DHCP6_STATE_SOLICITING:
      /* Timeout while soliciting. If we have a server, move to REQUEST.
       * Otherwise, retransmit SOLICIT. */
      if (dhcp6->server_duid_len > 0) {
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): got ADVERTISE, sending REQUEST\n"));
        dhcp6->tries = 0;
        dhcp6->elapsed_msecs = 0;
        dhcp6_stateful_request(netif, dhcp6);
      } else {
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): retrying SOLICIT\n"));
        dhcp6_solicit(netif, dhcp6);
      }
      break;
    case DHCP6_STATE_REQUESTING:
      if (dhcp6->tries >= DHCP6_REQ_MAX_RC) {
        /* Max retransmissions reached, restart from SOLICIT */
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): REQUEST max retries, restarting SOLICIT\n"));
        dhcp6->server_duid_len = 0;
        dhcp6->tries = 0;
        dhcp6->elapsed_msecs = 0;
        dhcp6_solicit(netif, dhcp6);
      } else {
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): retrying REQUEST\n"));
        dhcp6_stateful_request(netif, dhcp6);
      }
      break;
    case DHCP6_STATE_RENEWING:
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
        ("dhcp6_timeout(): retrying RENEW\n"));
      dhcp6_renew(netif, dhcp6);
      break;
    case DHCP6_STATE_REBINDING:
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
        ("dhcp6_timeout(): retrying REBIND\n"));
      dhcp6_rebind(netif, dhcp6);
      break;
    default:
      break;
  }
#endif /* LWIP_IPV6_DHCP6_STATEFUL */

#if LWIP_IPV6_DHCP6_STATELESS
  /* back-off period has passed, or server selection timed out */
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout(): retrying information request\n"));
    dhcp6_information_request(netif, dhcp6);
  }
#endif /* LWIP_IPV6_DHCP6_STATELESS */
}

/**
 * DHCPv6 timeout handling (this function must be called every 500ms,
 * see @ref DHCP6_TIMER_MSECS).
 *
 * A DHCPv6 server is expected to respond within a short period of time.
 * This timer checks whether an outstanding DHCPv6 request is timed out.
 */
void
dhcp6_tmr(void)
{
  struct netif *netif;
  /* loop through netif's */
  NETIF_FOREACH(netif) {
    struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
    /* only act on DHCPv6 configured interfaces */
    if (dhcp6 != NULL) {
      /* timer is active (non zero), and is about to trigger now */
      if (dhcp6->request_timeout > 1) {
        dhcp6->request_timeout--;
      } else if (dhcp6->request_timeout == 1) {
        dhcp6->request_timeout--;
        /* { dhcp6->request_timeout == 0 } */
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_tmr(): request timeout\n"));
        /* this client's request timeout triggered */
        dhcp6_timeout(netif, dhcp6);
      }
#if LWIP_IPV6_DHCP6_STATEFUL
      /* Handle lease timers when in BOUND state */
      if (dhcp6->state == DHCP6_STATE_BOUND) {
        /* Decrement lease timers */
        if (dhcp6->t1_timeout > 0) {
          dhcp6->t1_timeout--;
          if (dhcp6->t1_timeout == 0) {
            LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
              ("dhcp6_tmr(): T1 expired, starting RENEW\n"));
            dhcp6_renew(netif, dhcp6);
          }
        }
        if (dhcp6->t2_timeout > 0) {
          dhcp6->t2_timeout--;
          if (dhcp6->t2_timeout == 0 && dhcp6->state != DHCP6_STATE_RENEWING) {
            LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
              ("dhcp6_tmr(): T2 expired, starting REBIND\n"));
            dhcp6_rebind(netif, dhcp6);
          }
        }
        if (dhcp6->lease_timeout > 0) {
          dhcp6->lease_timeout--;
          if (dhcp6->lease_timeout == 0) {
            LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
              ("dhcp6_tmr(): lease expired, removing address\n"));
            if (dhcp6->addr_idx >= 0) {
              netif_ip6_addr_set_state(netif, dhcp6->addr_idx, IP6_ADDR_INVALID);
              dhcp6->addr_idx = -1;
            }
            /* Restart acquisition */
            dhcp6->server_duid_len = 0;
            dhcp6->tries = 0;
            dhcp6->elapsed_msecs = 0;
            dhcp6_set_state(dhcp6, DHCP6_STATE_STATEFUL_IDLE, "dhcp6_tmr_lease_expired");
          }
        }
      }
      /* Also handle T2 expiry during RENEWING */
      if (dhcp6->state == DHCP6_STATE_RENEWING && dhcp6->t2_timeout > 0) {
        dhcp6->t2_timeout--;
        if (dhcp6->t2_timeout == 0) {
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
            ("dhcp6_tmr(): T2 expired during RENEW, starting REBIND\n"));
          dhcp6_rebind(netif, dhcp6);
        }
      }
      /* Handle lease expiry during RENEWING or REBINDING */
      if ((dhcp6->state == DHCP6_STATE_RENEWING || dhcp6->state == DHCP6_STATE_REBINDING) &&
          dhcp6->lease_timeout > 0) {
        dhcp6->lease_timeout--;
        if (dhcp6->lease_timeout == 0) {
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_STATE,
            ("dhcp6_tmr(): lease expired during renew/rebind\n"));
          if (dhcp6->addr_idx >= 0) {
            netif_ip6_addr_set_state(netif, dhcp6->addr_idx, IP6_ADDR_INVALID);
            dhcp6->addr_idx = -1;
          }
          dhcp6->server_duid_len = 0;
          dhcp6->tries = 0;
          dhcp6->elapsed_msecs = 0;
          dhcp6_set_state(dhcp6, DHCP6_STATE_STATEFUL_IDLE, "dhcp6_tmr_lease_expired");
        }
      }
#endif /* LWIP_IPV6_DHCP6_STATEFUL */
    }
  }
}

#endif /* LWIP_IPV6 && LWIP_IPV6_DHCP6 */
