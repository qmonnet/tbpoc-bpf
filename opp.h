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

/* This header file defines the tables and the structures for conditions for
 * Open Packet Processor interface.
 */

#ifndef OPP_H
#define OPP_H

#include <stdint.h>
#include "bpf_api.h" /* File bpf_api.h from iproute2/include/bpf_api.h. */

/* Default available actions. Other user-defined action codes can be appended
 * here or defined in the main program, with higher values.
 */
#define ACTION_DROP    0
#define ACTION_FORWARD 1

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

/* Packet parsing state machine helpers. */
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

/* Structures for index and value (a.k.a key and leaf) for state table. */
struct StateTableKey {
  u16 ether_type;
  u16 __padding16;
  u32 ip_src;
  /* In use for port knocking, not used for token bucket
   *
   * u32 ip_dst;
   */
};

struct StateTableLeaf {
  u32 state;
  u32 __padding32;
  u64 r1;
  u64 r2;
};

/* Structures for index and value (a.k.a key and leaf) for XFSM stable. */
struct XFSMTableKey {
  u32 state;
  /* In use for port knocking, but not needed for token bucket.
   *
   * u8  l4_proto;
   * u8  __padding8;
   * u16 __padding16;
   * u16 src_port;
   * u16 dst_port;
   */
  u16 ether_type;
  u8 cond1;
  u8 cond2;
};

struct XFSMTableLeaf {
  u32 next_state;
  u32 packet_action;
  u32 update_function;
};

/* Encode conditions: condition evaluation result. */
enum evalcond {
  TRUE  = 1,
  FALSE = 2,
  ANY   = 3, /* Unused for now, we have no wildcard mechanism. */
  ERROR = 0,
};

/* Encode conditions: condition operator. */
enum opcond {
  EQ,
  NE,
  LT,
  LE,
  GT,
  GE,
};

static int check_condition(u64 op, u64 a, u64 b) {
  switch (op) {
    case EQ:
      if (a == b) return TRUE; else return FALSE;
    case NE:
      if (a != b) return TRUE; else return FALSE;
    case LT:
      if (a <  b) return TRUE; else return FALSE;
    case LE:
      if (a <= b) return TRUE; else return FALSE;
    case GT:
      if (a >  b) return TRUE; else return FALSE;
    case GE:
      if (a >= b) return TRUE; else return FALSE;
    default:
      return -1;
  }
}

#endif /* OPP_H */
