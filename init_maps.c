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

/* This program contains the code needed to initialize an eBPF map, the XFSM
 * map, in order to run the token bucket proof-of-concept stateful application.
 * The state map starts empty.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Const and struct definitions */

#define IPV4 0x0800
#define IPV6 0x86DD
#define ARP  0x0806
#define TCP  0x06
#define UDP  0x11

enum actions {
  DROP    = 0,
  FORWARD = 1
};

enum states {
  ZERO,
  ONE,
};

enum updates {
  UPDATE_CASE_1,
  UPDATE_CASE_2,
  UPDATE_CASE_3
};

enum boolean {
  TRUE  = 1,
  FALSE = 2,
  ANY   = 3,
  ERROR = 0,
};

struct StateTableKey {
  u16 ether_type;
  u16 __padding16;
  u32 ip_src;
};
struct StateTableLeaf {
  u64 r1;
  u64 r2;
  int state;
};

struct XFSMTableKey {
  int state;
  u16 ether_type;
  u8 cond1;
  u8 cond2;
};
struct XFSMTableLeaf {
  int next_state;
  int packet_action;
  int update_function;
};

/* Some helpers */

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
  return syscall(__NR_bpf, cmd, attr, size);
#else
  fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
  errno = ENOSYS;
  return -1;
#endif
}

__u64 bpf_ptr_to_u64(const void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

int bpf_update_elem(int fd, void *key, void *value, u64 flags)
{
  union bpf_attr attr = {};
  attr.map_fd = fd;
  attr.key    = bpf_ptr_to_u64(key);
  attr.value  = bpf_ptr_to_u64(value);;
  attr.flags  = flags;

  static int nb = 0;
  nb++;
  int ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  if (ret < 0) {
    fprintf(stderr, "Map update #%d failed: %s\n", nb, strerror(errno));
  }
  return ret;
}

/* Main function */

int main (void) {
  union bpf_attr attr_obj = {};
  int map_fd;
  struct XFSMTableKey xtkey = {};
  struct XFSMTableLeaf xtleaf = {};

  // char *stpath = "/sys/fs/bpf/tc/globals/state_table";
  char *xtpath = "/sys/fs/bpf/tc/globals/xfsm_table";

  /* XFSM table */

  attr_obj.map_fd = 0;
  attr_obj.pathname = bpf_ptr_to_u64(xtpath);
  map_fd = bpf(BPF_OBJ_GET, &attr_obj, sizeof(attr_obj));
  if (map_fd <= 0) {
    fprintf(stderr, "Getting XFSM map failed: %s\n", strerror(errno));
    return -1;
  }

  xtkey.state      = ZERO;
  xtkey.ether_type = IPV4;
  xtkey.cond1      = TRUE;
  xtkey.cond2      = TRUE;

  xtleaf.next_state      = ONE;
  xtleaf.packet_action   = FORWARD;
  xtleaf.update_function = UPDATE_CASE_2;

  if (bpf_update_elem(map_fd, &xtkey, &xtleaf, BPF_ANY))
    return -1;

  xtkey.state      = ONE;
  xtkey.ether_type = IPV4;
  xtkey.cond1      = TRUE;
  xtkey.cond2      = FALSE;

  xtleaf.next_state      = ONE;
  xtleaf.packet_action   = FORWARD;
  xtleaf.update_function = UPDATE_CASE_2;

  if (bpf_update_elem(map_fd, &xtkey, &xtleaf, BPF_ANY))
    return -1;

  xtkey.state      = ONE;
  xtkey.ether_type = IPV4;
  xtkey.cond1      = TRUE;
  xtkey.cond2      = TRUE;

  xtleaf.next_state      = ONE;
  xtleaf.packet_action   = FORWARD;
  xtleaf.update_function = UPDATE_CASE_1;

  if (bpf_update_elem(map_fd, &xtkey, &xtleaf, BPF_ANY))
    return -1;

  xtkey.state      = ONE;
  xtkey.ether_type = IPV4;
  xtkey.cond1      = FALSE;
  xtkey.cond2      = TRUE;

  xtleaf.next_state      = ONE;
  xtleaf.packet_action   = DROP;
  xtleaf.update_function = UPDATE_CASE_3;

  if (bpf_update_elem(map_fd, &xtkey, &xtleaf, BPF_ANY))
    return -1;

  return 0;
}
