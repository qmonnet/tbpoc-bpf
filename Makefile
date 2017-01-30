#    GNU GENERAL PUBLIC LICENSE, Version 2
#
#    Copyright (C) 2017, 6WIND S.A.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


tokenbucket.o: tokenbucket.c bpf_api.h bpf_elf.h opp.h proto.h
	clang -O2 -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

.PHONY: clean

clean:
	rm -f tokenbucket.o
