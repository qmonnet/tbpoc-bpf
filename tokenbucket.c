/*-
 *    GNU GENERAL PUBLIC LICENSE, Version 2
 *
 *    Copyright (C) 2017, 6WIND S.A.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* This file is meant to be compiled into eBPF bytecode. It implements a
 * two-color token bucket, based on the Open Packet Processor interface.
 */

#include "proto.h"
#include "opp.h"

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
  __u8  h_dest[ETH_ALEN];
  __u8  h_source[ETH_ALEN];
  __u16 h_proto;
};

/* State table */
struct bpf_elf_map __section("maps") state_table = {
  .type       = BPF_MAP_TYPE_HASH,
  .size_key   = sizeof(struct StateTableKey),
  .size_value = sizeof(struct StateTableLeaf),
  .max_elem   = 256,
  .pinning    = PIN_GLOBAL_NS,
};

/* XFSM table */
struct bpf_elf_map __section("maps") xfsm_table = {
  .type       = BPF_MAP_TYPE_HASH,
  .size_key   = sizeof(struct XFSMTableKey),
  .size_value = sizeof(struct XFSMTableLeaf),
  .max_elem   = 256,
  .pinning    = PIN_GLOBAL_NS,
};

/* ------------------ */
/* This is totally application dependent */
#define TB_TOKEN_NB 5ULL
#define TB_TOKEN_REGEN 1ULL
#define R 1000000000/TB_TOKEN_REGEN // ns^-1
#define B (TB_TOKEN_NB-1)*R // ns

enum states {
  ZERO,
  ONE,
};

enum updates {
  UPDATE_CASE_1,
  UPDATE_CASE_2,
  UPDATE_CASE_3
};
/* ------------------ */

__section_cls_entry
int cls_entry(struct __sk_buff *skb) {
  void *cursor   = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  int current_state;

  /* Initialize most fields to 0 in case we do not parse associated headers.
   * The alternative is to set it to 0 once we know we will not meet the header
   * (e.g. when we see ARP, we won't have dst IP / port...). It would prevent
   * to affect a value twice in some cases, but it is prone to error when
   * adding parsing for other protocols.
   */
  struct StateTableKey state_idx;
  // state_idx.ether_type // Will be set anyway
  state_idx.__padding16 = 0;
  state_idx.ip_src = 0;
  struct StateTableLeaf *state_val;

  struct XFSMTableKey  xfsm_idx;
  // xfsm_idx.state // Will be set anyway before XFSM lookup
  struct XFSMTableLeaf *xfsm_val;

  struct ethernet_t *ethernet;
  struct ip_t       *ip;

  u64 tnow = ktime_get_ns();
  u64 tmin, tmax;

  /* Headers parsing */

  ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if ((void *)ethernet + sizeof(*ethernet) > data_end)
    goto EOP;

  state_idx.ether_type = ntohs(ethernet->type);

  switch (state_idx.ether_type) {
    case ETH_P_IP: {
      ip = cursor_advance(cursor, sizeof(*ip));
      if ((void *)ip + sizeof(*ip) > data_end)
        goto EOP;

      state_idx.ip_src = ntohl(ip->src);
      break;
    }
    case ETH_P_ARP:
    default: goto EOP;
  }

  /* State table lookup */

  state_val = map_lookup_elem(&state_table, &state_idx);

  if (state_val) {
    current_state = state_val->state;
    tmin          = state_val->r1;
    tmax          = state_val->r2;
  } else {
    current_state = ZERO;
    tmin          = tnow - B;
    tmax          = tnow + R;
  }

  /* Evaluate conditions */

  int cond1 = check_condition(GE, tnow, tmin);
  int cond2 = check_condition(LE, tnow, tmax);
  if (cond1 == ERROR || cond2 == ERROR)
    goto error;

  /* XFSM table lookup */

  xfsm_idx.state = current_state;
  xfsm_idx.ether_type = ETH_P_IP;
  xfsm_idx.cond1 = cond1;
  xfsm_idx.cond2 = cond2;
  xfsm_val = map_lookup_elem(&xfsm_table, &xfsm_idx);

  if (!xfsm_val)
    goto error;

  /* Apply update functions */

  struct StateTableLeaf updated_state = { };
  updated_state.state = xfsm_val->next_state;
  updated_state.r1 = tmin;
  updated_state.r2 = tmax;

  /* Run update function we obtained from the XFSM table. */
  switch (xfsm_val->update_function) {
    /* Packet hit the window. */
    case UPDATE_CASE_1:
      updated_state.r1 = tmin + R;
      updated_state.r2 = tmax + R;
      break;
    /* Packet hit "after" the window. */
    case UPDATE_CASE_2:
      updated_state.r1 = tnow - B;
      updated_state.r2 = tnow + R;
      break;
    /* Packet hit "before" the window. */
    case UPDATE_CASE_3:
      break;
    default:
      goto error;
  }

  /* Update state table. We re-use the StateTableKey we had initialized
   * already. We update this rule with the new state provided by XFSM
   * table, and with the registers updated as stated by the XFSM table as well.
   */
  map_update_elem(&state_table, &state_idx, &updated_state, BPF_ANY);

  /* Process packet */

  /* At last, execute the action for the current state, that we obtained
   * from the XFSM table.
   * Users should add new actions here.
   */
  switch (xfsm_val->packet_action) {
    case ACTION_DROP:
      return TC_ACT_SHOT;
    case ACTION_FORWARD:
      return TC_ACT_OK;
    default:
      goto error;
  }

EOP:
  return TC_ACT_OK;

error:
  /* For cases that should not be reached. */
  return TC_ACT_UNSPEC;
}

/* Need to be GPL so that we can use the map helpers. */
BPF_LICENSE("GPL");
