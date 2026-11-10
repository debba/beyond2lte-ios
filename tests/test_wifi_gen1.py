#!/usr/bin/env python3
"""Exercise actual Gen1 and read-only endpoint flows with strict MMIO guards."""
import os
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
data_header = (repo / 'xnu-overlay/osfmk/arm64/b2l_wifi_phy_data.h').read_text()
for name, count, digest in [
    ('b2l_wifi_cmn', 48, 'd2133509bb6aa73d82ece56d896a8c7f5867681506fd981f093582bb00d0302c'),
    ('b2l_wifi_trsv', 80, '444696357d4794f501d3996c64427188a806ee78a0b2e0f0de2e25d58742c180'),
]:
    match = re.search(name + r'\[\d+\]\s*=\s*\{(.*?)\};', data_header, re.S)
    assert match
    values = bytes(int(value, 16) for value in re.findall(r'0x[0-9a-fA-F]+', match.group(1)))
    assert len(values) == count and hashlib.sha256(values).hexdigest() == digest
source = (repo / 'xnu-overlay/osfmk/arm64/b2l_wifi_diag.c').read_text()
source = '\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
rd = 'return *(volatile const uint32_t *)(region->mapped + offset);'
wr = '''    *(volatile uint32_t *)(region->mapped + offset) = value;
    __asm__ volatile ("dsb sy" ::: "memory");'''
assert source.count(rd) == source.count(wr) == 1
source = source.replace(rd, 'return host_read(region->mapped, offset);')
source = source.replace(wr, '    host_write(region->mapped, offset, value);')

pre = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "b2l_wifi_phy_data.h"
typedef uintptr_t vm_offset_t;
typedef unsigned long vm_size_t;
#define VM_WIMG_IO 0x66
#define NSEC_PER_MSEC 1000000u
static _Alignas(16384) uint32_t memory[11][4096];
static const uintptr_t physical[] = {
    0x15860000, 0x10430000, 0x13c40000, 0x13c00000, 0x13ed0000,
    0x13ef0000, 0x13ee0000, 0x13c10000, 0x13f00000, 0x14ffc000, 0x14400000
};
static unsigned maps, unmaps, fail_map, writes, drop_write, link_polls;
static unsigned trained, scenario, gen1_reads;
static unsigned invalid_profile_once;
static unsigned mode = 4, endpoint_reads, endpoint_fault, atu_enable_write, fault_served;
static uint32_t atu[7];
static uint32_t atu0[7];
static unsigned chip_reads, chip_fault, config_writes;
static unsigned erom_reads, erom_fault;
static uint32_t erom[896];
static unsigned wrapper_reads[2], r4_cap_reads, core_fault;
static uint32_t wrapper_values[2][3];
static unsigned bank_reads, bank_writes, bank_index, tcm_fault;
static uint32_t bank_info[13];
static uint32_t original_viewport;
static uint32_t original_endpoint_command, original_bar0;
static uint64_t enabled_at;
static uint64_t now_us;
static char logs[131072];
static unsigned log_size;
static void b2l_early_trace(const char *fmt, ...) {
    va_list args; va_start(args, fmt);
    int n = vsnprintf(logs + log_size, sizeof(logs) - log_size, fmt, args);
    va_end(args); assert(n >= 0 && (unsigned)n < sizeof(logs) - log_size);
    log_size += (unsigned)n;
}
static int PE_parse_boot_argn(const char *name, void *value, unsigned size) {
    assert(!strcmp(name, "b2l_wifi_diag") && size == 4); *(uint32_t *)value = mode; return 1;
}
static uint64_t mach_absolute_time(void) { return now_us; }
static void clock_interval_to_deadline(unsigned n, unsigned unit, uint64_t *at) {
    assert((n == 500 || (mode >= 5 && n == 100)) && unit == NSEC_PER_MSEC); *at = now_us + n * 1000;
}
static void delay(unsigned us) { assert(us == 10 || us == 20 || us == 100); now_us += us; }
static void delay_for_interval(unsigned n, unsigned unit) {
    assert(unit == NSEC_PER_MSEC && (n == 1 || n == 20 || n == 200 ||
        (mode >= 5 && (n == 9 || n == 100)))); now_us += n * 1000;
}
static uintptr_t ml_io_map_unmappable(uintptr_t pa, unsigned long size, unsigned flags) {
    assert(maps < (mode >= 6 ? 11u : mode + 5) && pa == physical[maps] && size == 0x4000 && flags == VM_WIMG_IO);
    unsigned index = maps++;
    return maps == fail_map ? 0 : (uintptr_t)memory[index];
}
static void ml_io_unmap(uintptr_t va, unsigned long size) {
    unsigned successful = maps - (fail_map && fail_map <= maps ? 1 : 0);
    assert(size == 0x4000 && unmaps < successful);
    assert(va == (uintptr_t)memory[successful - ++unmaps]);
}
static unsigned region_index(uintptr_t address) {
    assert(maps == (mode >= 6 ? 11u : mode + 5) && !fail_map && !unmaps);
    for (unsigned i = 0; i < 11; i++) if (address == (uintptr_t)memory[i]) return i;
    assert(0); return 99; /* No config/BAR/ATU/SysMMU/CMU-other mappings. */
}
static void powered(unsigned index) {
    if (index < 4) return;
    assert(now_us >= 201000);
    assert(memory[0][0x71c/4] & 1);
    assert(((memory[1][0x80/4] >> 20) & 15) == 1 && (memory[1][0x84/4] & 32));
    assert(((memory[2][0x20/4] >> 8) & 15) == 1);
    if (index >= 8) assert(memory[6][0xec/4] & 8); /* DBI/config accesses ignore RX idle. */
}
static int valid_link_setup(void) {
    for (unsigned i = 0; i < sizeof(b2l_wifi_cmn); i++)
        if (memory[5][i] != b2l_wifi_cmn[i]) return 0;
    for (unsigned i = 0; i < sizeof(b2l_wifi_trsv); i++)
        if (memory[5][0x30+i] != b2l_wifi_trsv[i]) return 0;
    return (memory[2][0x24/4] & 4) && (memory[2][0x20/4] & 15) == 2 &&
        (memory[2][0x28/4] & 15) == 3 && (memory[7][0x1044/4] & 2) &&
        (memory[7][0x1050/4] & 0x10fe) == (scenario == 8 ? 0x1004u : 0x100cu) &&
        memory[4][0x1d0/4] == 1 && memory[4][0x288/4] == 1 &&
        memory[4][0x28c/4] == 1 && memory[4][0x290/4] == 1 &&
        !(memory[4][0x0c/4] | memory[4][0x10/4] | memory[4][0x14/4]) &&
        memory[6][0xf8/4] == 0x70 && memory[6][0x100/4] == 0x87 &&
        memory[6][0x104/4] == 0x50 && !(memory[6][0xd0/4] & 0xc0) &&
        !(memory[8][0x04/4] & 0x145) && (memory[8][0xa0/4] & 15) == 1 &&
        (memory[8][0x710/4] & 0x3f0000) == 0x10000 &&
        (memory[8][0x80c/4] & 0x1f00) == 0x100 && memory[8][0xb40/4] == 26;
}
static uint32_t host_read(uintptr_t address, unsigned off) {
    unsigned i = region_index(address); assert(!(off & 3) && off < 0x4000); powered(i);
    int allowed = (i == 0 && off == 0x71c) ||
        (i == 1 && (off == 0x80 || off == 0x84)) ||
        (i == 2 && (off == 0x20 || off == 0x24 || off == 0x28)) ||
        (i == 3 && ((off >= 0x2030 && off <= 0x2044) || (off >= 0x3034 && off <= 0x3044))) ||
        (i == 4 && (off == 0x2c || off == 0x74 || off == 0x1d0 || off == 0x288 ||
                    off == 0x28c || off == 0x290 || off == 0xc || off == 0x10 || off == 0x14 ||
                    off == 0x18 || off == 0xf4 || off == 0x1b8 || off == 0x2c8)) ||
        (i == 5 && (off == 0x80 || off == 0x15c)) ||
        (i == 6 && (off == 0xc || off == 0xd0 || off == 0xec || off == 0x100 || off == 0x104)) ||
        (i == 7 && (off == 0x1044 || off == 0x1050)) ||
        (i == 8 && (off == 0 || off == 4 || off == 0x44 || off == 0x7c || off == 0x80 ||
                    off == 0xa0 || off == 0x710 || off == 0x80c || off == 0x8bc || off == 0xb40 ||
                    (mode >= 5 && (off == 0x0c || off == 0x18 || (off >= 0x900 && off <= 0x91c))))) ||
        (mode >= 5 && i == 9 && (off == 0x2000 || off == 0x2004 || off == 0x2008 || off == 0x202c ||
            (mode >= 6 && (off == 0x2010 || off == 0x2014 || off == 0x2080)))) ||
        (mode >= 6 && i == 10 && (off == 0 || off == 4 || off == 0xfc ||
            (mode >= 7 && memory[9][0x2080/4] == 0x18111000 && off < 0xe00) ||
            (mode >= 8 && (memory[9][0x2080/4] == 0x18102000 || memory[9][0x2080/4] == 0x18103000) &&
                (off == 0x408 || off == 0x500 || off == 0x800)) ||
            (mode == 9 && memory[9][0x2080/4] == 0x18002000 && (off == 0x40 || off == 0x44))));
    assert(allowed);
    if (i == 8 && (off == 0x0c || off == 0x18 || (off >= 0x900 && off <= 0x91c)))
        assert(mode >= 5 && trained && valid_link_setup());
    if (i >= 5) gen1_reads++;
    if (mode >= 5 && atu_enable_write) {
        if (i == 4 && off == 0x74 &&
            (endpoint_fault == 5 || (endpoint_fault == 6 && endpoint_reads))) return 0;
        if (i == 8 && off == 0x04 && endpoint_fault == 15 && atu[1]) return 6;
        if (i == 8 && off == 0x80 && endpoint_fault == 17) return 0x120000;
        if (mode >= 6 && chip_fault == 9 && i == 4 && off == 0x74 &&
            (memory[9][0x2004/4] & 7) == 2) return 0;
        if (mode >= 7 && erom_fault == 4 && erom_reads && i == 4 && off == 0x74) return 0;
        if (mode >= 8 && core_fault == 7 && wrapper_reads[0] && i == 4 && off == 0x74) return 0;
        if (mode == 9 && tcm_fault == 5 && bank_reads && i == 4 && off == 0x74) return 0;
    }
    if (i == 9) {
        assert(!(mode >= 6 && chip_fault == 9 && (memory[9][0x2004/4] & 7) == 2));
        assert(!(mode >= 7 && erom_fault == 4 && erom_reads));
        assert(!(mode >= 8 && core_fault == 7 && wrapper_reads[0]));
        assert(!(mode == 9 && tcm_fault == 5 && bank_reads));
        static const unsigned expected[] = { 0x2000, 0x2004, 0x2008, 0x202c };
        if (endpoint_reads < 4) assert(off == expected[endpoint_reads++]);
        else assert(mode >= 6 && (off == 0x2004 || off == 0x2010 || off == 0x2014 || off == 0x2080));
        assert(trained && valid_link_setup() && now_us >= enabled_at + 100000);
        assert(memory[8][0x900/4] == 1 && (memory[8][0x18/4] & 0xffffff) == 0x10100);
        assert(!(memory[8][4/4] & 0x145));
        assert(atu[0] == 4 && atu[1] == 0x80000000 && atu[2] == 0x14ffe000 &&
            atu[3] == 0 && atu[4] == 0x14ffefff && atu[5] == 0x01000000 && atu[6] == 0);
        if (endpoint_fault == 11) now_us += 110000;
        if (off == 0x2000 && endpoint_fault == 1) return 0x123414e4;
        if (off == 0x2000 && endpoint_fault == 2) return UINT32_MAX;
        if (off == 0x2000 && endpoint_fault == 14) return 0;
        if (off == 0x2004 && endpoint_fault == 3) return 4;
        if (off == 0x202c && endpoint_fault == 4) return 0x000014e4;
        if (off == 0x2008 && endpoint_fault == 13) return UINT32_MAX;
        return memory[i][off/4];
    }
    if (i == 10) {
        if (mode >= 8 && (memory[9][0x2080/4] == 0x18102000 || memory[9][0x2080/4] == 0x18103000)) {
            unsigned core = memory[9][0x2080/4] == 0x18103000 ? 0 : 1;
            static const unsigned expected[] = { 0x408, 0x500, 0x800 };
            assert(chip_reads == 3 && erom_reads == 133 && wrapper_reads[core] < 3);
            assert(off == expected[wrapper_reads[core]] && (memory[9][0x2004/4] & 7) == 2);
            assert(memory[8][0x900/4] == 1 && atu[1] == 0x80000000 && atu0[1] == 0x80000000);
            if (core == 1) assert(wrapper_reads[0] == 3);
            uint32_t value = wrapper_values[core][wrapper_reads[core]++];
            if (core_fault == 6) now_us += 110000;
            return value;
        }
        if (mode == 9 && memory[9][0x2080/4] == 0x18002000 && (off == 0x40 || off == 0x44)) {
            assert(r4_cap_reads == 1 && (wrapper_values[1][0] & 0x23) == 0x21 && !(wrapper_values[1][2] & 1));
            assert((memory[9][0x2004/4] & 7) == 2 && atu0[1] == 0x80000000);
            if (off == 0x40) {
                if (tcm_fault == 1 && !bank_writes) return UINT32_MAX;
                if (tcm_fault == 8 && !bank_writes) return 13;
                if (tcm_fault == 7 && bank_writes == 1) return bank_index ^ 1;
                return bank_index;
            }
            assert(bank_reads < 13 && bank_index == bank_reads && bank_writes);
            uint32_t info = bank_info[bank_reads++];
            if (tcm_fault == 4) now_us += 110000;
            return (tcm_fault == 2 && bank_reads == 1) || (tcm_fault == 3 && bank_reads == 6) ? UINT32_MAX : info;
        }
        if (mode >= 8 && memory[9][0x2080/4] == 0x18002000) {
            assert(off == 4 && wrapper_reads[0] == 3 && wrapper_reads[1] == 3 && !r4_cap_reads++);
            assert((wrapper_values[1][0] & 3) == 1 && !(wrapper_values[1][2] & 1));
            assert((memory[9][0x2004/4] & 7) == 2 && atu0[1] == 0x80000000);
            return core_fault == 5 ? UINT32_MAX : tcm_fault == 9 ? 0x351584 : 0x351585;
        }
        if (mode >= 7 && memory[9][0x2080/4] == 0x18111000) {
            assert(chip_reads == 3 && off == erom_reads * 4 && off < 0xe00 && erom_reads < 896);
            assert((memory[9][0x2004/4] & 7) == 2 && memory[9][0x2010/4] == 0x14400004);
            assert(!memory[9][0x2014/4] && memory[8][0x900/4] == 1);
            assert(atu[1] == 0x80000000 && atu0[1] == 0x80000000 && atu0[0] == 0 &&
                atu0[2] == 0x14400000 && atu0[4] == 0x14400fff && atu0[5] == 0x14400000);
            if (erom_fault == 3) now_us += 110000;
            return erom[erom_reads++];
        }
        static const unsigned expected[] = { 0, 4, 0xfc };
        assert(mode >= 6 && chip_reads < 3 && off == expected[chip_reads++]);
        assert(endpoint_reads == 4 && memory[8][0x900/4] == 1);
        assert((memory[9][0x2004/4] & 7) == 2 && memory[9][0x2010/4] == 0x14400004);
        assert(!memory[9][0x2014/4] && memory[9][0x2080/4] == 0x18000000);
        assert(atu[1] == 0x80000000 && atu0[0] == 0 && atu0[1] == 0x80000000 &&
            atu0[2] == 0x14400000 && !atu0[3] && atu0[4] == 0x14400fff &&
            atu0[5] == 0x14400000 && !atu0[6]);
        if (chip_fault == 1 && !off) return UINT32_MAX;
        if (chip_fault == 2 && !off) return 0x14834376;
        if (chip_fault == 3 && off == 4) return UINT32_MAX;
        if (chip_fault == 4 && off == 0xfc) return UINT32_MAX;
        if (chip_fault == 5) now_us += 110000;
        return memory[i][off/4];
    }
    if (i == 4 && off == 0x74 && (memory[4][0x2c/4] & 1)) {
        if (!trained) link_polls++;
        if (scenario == 4) now_us += 300000; /* Preemption must not extend polling indefinitely. */
        if (scenario != 1 && scenario != 4 && link_polls >= 3 && valid_link_setup()) {
            trained = 1;
            return 0xf15411;
        }
    }
    if (i == 8 && off == 0x80 && trained && (memory[4][0x2c/4] & 1)) {
        if (scenario == 3) return UINT32_MAX;
        return (memory[8][off/4] & 0xffff) | ((scenario == 2 ? 2u : 1u) << 16) | (1u << 20);
    }
    if (i == 8 && off == 0 && scenario == 5) return UINT32_MAX;
    if (i == 8 && mode >= 5 && off >= 0x904 && off <= 0x91c) {
        if (memory[8][0x900/4] == 0) {
            assert(mode >= 6);
            return atu0[(off - 0x904)/4];
        }
        assert(memory[8][0x900/4] == 1); /* No inbound/other regions. */
        if (endpoint_fault == 12 && off == 0x908 && atu_enable_write && !fault_served++) return UINT32_MAX;
        if (endpoint_fault == 19 && off == 0x914) return UINT32_MAX;
        return atu[(off - 0x904)/4];
    }
    if (i == 7 && off == 0x1050 && invalid_profile_once) {
        invalid_profile_once = 0;
        return UINT32_MAX;
    }
    return memory[i][off/4];
}
static void host_write(uintptr_t address, unsigned off, uint32_t value) {
    unsigned i = region_index(address); assert(!(off & 3) && off < 0x4000); powered(i);
    uint32_t before = memory[i][off/4], mask = 0;
    if (i == 10) {
        assert(mode == 9 && off == 0x40 && value < 13);
        assert(memory[9][0x2080/4] == 0x18002000 && (memory[9][0x2004/4] & 7) == 2);
        assert(r4_cap_reads == 1 && (wrapper_values[1][0] & 0x23) == 0x21 && !(wrapper_values[1][2] & 1));
        assert(atu[1] == 0x80000000 && atu0[1] == 0x80000000 && memory[8][0x900/4] == 1);
        assert(!(tcm_fault == 5 && bank_reads));
        writes++; bank_writes++;
        if (writes == drop_write || (tcm_fault == 6 && bank_reads == 13 && value == 7)) return;
        bank_index = value;
        if (tcm_fault == 11 && bank_writes == 1) now_us += 110000;
        return;
    }
    if (i == 9) {
        assert(mode >= 6 && endpoint_reads == 4 && memory[8][0x900/4] == 1 && atu[1] == 0x80000000);
        assert(off == 0x2004 || off == 0x2010 || off == 0x2014 || off == 0x2080);
        if (off == 0x2004) {
            assert(!(value >> 16) && ((value & 7) == 0 || (value & 7) == 2));
            assert(!((before ^ value) & 0xfff8)); /* Preserve unrelated command bits. */
        }
        else assert(!(memory[9][0x2004/4] & 7)); /* Never move a live BAR. */
        if (off == 0x2010) assert(value == 4 || value == 0x14400004);
        if (off == 0x2014) assert(value == 0);
        if (off == 0x2080) assert(value == 0x18000000 || value == 0x18001000 || (mode >= 7 && value == 0x18111000) ||
            (mode >= 8 && (value == 0x18103000 || value == 0x18102000 || value == 0x18002000)));
        writes++; config_writes++;
        if (writes == drop_write) return;
        if (chip_fault == 6 && off == 0x2004 && !value && (before & 7) == 2) return;
        if (chip_fault == 7 && off == 0x2080 && value == 0x18001000) return;
        if (mode >= 7 && erom_fault == 10 && erom_reads && off == 0x2080 && value == 0x18001000) return;
        if (mode >= 7 && erom_fault == 12 && erom_reads && off == 0x2004 && !value) return;
        if (mode >= 8 && core_fault == 8 && r4_cap_reads && off == 0x2080 && value == 0x18001000) return;
        if (mode >= 8 && core_fault == 9 && r4_cap_reads && off == 0x2004 && !value) return;
        memory[i][off/4] = off == 0x2004 ? (before & 0xffff0000) | value : value;
        return;
    }
    if (i == 0 && off == 0x71c) mask = 1;
    if (i == 1 && off == 0x80) mask = 15u << 20;
    if (i == 1 && off == 0x84) mask = 32;
    if (i == 2 && off == 0x20) mask = 15u | (15u << 8);
    if (i == 2 && off == 0x24) mask = 4;
    if (i == 2 && off == 0x28) mask = 15;
    if (i == 4 && (off == 0xc || off == 0x10 || off == 0x14)) { mask = UINT32_MAX; assert(!value); }
    if (i == 4 && off == 0x18) mask = 2;
    if (i == 4 && off == 0xf4) mask = 0x11;
    if (i == 4 && off == 0x1b8) mask = 3;
    if (i == 4 && off == 0x2c8) mask = 0xfff;
    if (i == 4 && (off == 0x2c || off == 0x1d0 || off == 0x288 || off == 0x28c || off == 0x290)) mask = 1;
    if (i == 5 && off <= 0x1fc) { mask = 255; assert(value <= 255); }
    if (i == 6 && off == 0xec) mask = 8;
    if (i == 6 && (off == 0x100 || off == 0x104 || off == 0xf8)) mask = 255;
    if (i == 6 && off == 0xc) mask = 0x12;
    if (i == 6 && off == 0xd0) mask = 0xc0;
    if (i == 7 && off == 0x1044) mask = 2;
    if (i == 7 && off == 0x1050) mask = 0x10fe;
    if (i == 8) {
        if (mode >= 5 && off >= 0x904 && off <= 0x91c) {
            assert(trained && !(memory[8][4/4] & 0x145));
            if (memory[8][0x900/4] == 0) {
                assert(mode >= 6);
                static const uint32_t allowed[] = { 0, 0x80000000, 0x14400000, 0, 0x14400fff, 0x14400000, 0 };
                unsigned slot = (off - 0x904)/4;
                assert(value == allowed[slot] || (off == 0x908 && value == 0));
                writes++;
                if (chip_fault == 8 && off == 0x908 && !value && atu0[1]) return;
                if (chip_fault == 14 && off == 0x908 && value) return;
                if (writes != drop_write) atu0[slot] = value;
                return;
            }
            assert(memory[8][0x900/4] == 1);
            static const uint32_t allowed[] = { 4, 0x80000000, 0x14ffe000, 0, 0x14ffefff, 0x01000000, 0 };
            unsigned slot = (off - 0x904)/4;
            assert(value == allowed[slot] || (off == 0x908 && value == 0));
            writes++;
            if (off == 0x908 && value == 0x80000000) {
                atu_enable_write = writes;
                enabled_at = now_us;
            }
            if (writes == drop_write || (endpoint_fault == 9 && off == 0x908 && value) ||
                (endpoint_fault == 10 && off == 0x908 && !value && atu[1])) return;
            atu[slot] = value;
            return;
        }
        if (mode >= 5 && off == 0x18) mask = 0xffffff;
        if (mode >= 5 && off == 0x900) { mask = UINT32_MAX; assert(value == original_viewport || value == 1 || (mode >= 6 && value == 0)); }
        if (off == 4 || off == 0x44 || off == 0x80 || off == 0xa0) {
            assert(!(value >> 16));
            if (off == 4) assert(!(value & 0x145));
            if (off == 0x44) assert(!(value & 0x8000));
            writes++;
            if (writes != drop_write) {
                memory[i][off/4] = (before & 0xffff0000) | value;
                if (off == 0x44) memory[i][off/4] |= before & 0x8000; /* W1C zero preserves PME_Status. */
            }
            return;
        }
        if (off == 0x710) mask = 0x3f0000;
        if (off == 0x80c) mask = 0x21f00;
        if (off == 0x7c) { mask = 0x383ff; assert(memory[8][0x8bc/4] & 1); }
        if (off == 0x8bc) mask = 1;
        if (off == 0xb40) { mask = UINT32_MAX; assert(value == 26); }
    }
    assert(mask && !((before ^ value) & ~mask));
    writes++;
    if (scenario == 6 && i == 4 && off == 0x2c && before == 1 && value == 0) return;
    if (scenario == 7 && i == 5 && off == 0x80 && value == 0xc1) return;
    if (writes != drop_write) {
        memory[i][off/4] = value;
        if (i == 7 && off == 0x1050 && value == 0x1d0c) {
            if (scenario == 8 || scenario == 9) memory[i][off/4] &= ~8u;
            if (scenario == 10) memory[i][off/4] &= ~4u;
            if (scenario == 11) invalid_profile_once = 1;
        }
    }
}
'''

post = r'''
static void reset(unsigned which, unsigned failure) {
    maps = unmaps = writes = drop_write = link_polls = 0;
    trained = gen1_reads = log_size = invalid_profile_once = 0;
    endpoint_reads = endpoint_fault = atu_enable_write = fault_served = 0;
    enabled_at = 0; memset(atu, 0, sizeof(atu));
    memset(atu0, 0, sizeof(atu0)); chip_reads = chip_fault = config_writes = 0;
    erom_reads = erom_fault = 0; memset(erom, 0, sizeof(erom));
    wrapper_reads[0] = wrapper_reads[1] = r4_cap_reads = core_fault = 0;
    bank_reads = bank_writes = tcm_fault = 0; bank_index = 7;
    for (unsigned b = 0; b < 13; b++) bank_info[b] = b < 5 ? 0x203 : 0xf;
    memset(wrapper_values, 0, sizeof(wrapper_values)); wrapper_values[0][0] = 1; wrapper_values[1][0] = 0x21;
    erom[0] = 0x4bf80001; erom[1] = 0x39000201; erom[2] = 0x18000005;
    erom[3] = 0x4bf83c01; erom[4] = 0x42000201; erom[5] = 0x18001005; erom[6] = 0xf;
    original_viewport = 0;
    now_us = 0; fail_map = failure; scenario = which;
    memset(memory, 0, sizeof(memory)); memset(logs, 0, sizeof(logs));
    memory[1][0x84/4] = 1;
    for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
    for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
    memory[4][0x74/4] = 0xf15400;
    memory[4][0x1d0/4] = memory[4][0x288/4] = memory[4][0x28c/4] = memory[4][0x290/4] = 1;
    memory[4][0xc/4] = memory[4][0x10/4] = memory[4][0x14/4] = 0x55;
    memory[4][0x18/4] = 0x12; memory[4][0xf4/4] = 0x20;
    memory[4][0x1b8/4] = 0x80; memory[4][0x2c8/4] = 0xaaaa0555;
    memory[7][0x1044/4] = 0x8040; memory[7][0x1050/4] = 0x80000101;
    if (which >= 8 && which <= 11) memory[7][0x1050/4] = which == 9 ? 0x1d82 : 0x1d02;
    memory[8][0] = 0x123416c3;
    memory[8][4/4] = 0xdead0144; /* BME, parity and SERR must be cleared before training. */
    memory[8][0x44/4] = 0xbeef8003; /* PME_Status must not be acknowledged by copying it. */
    memory[8][0x18/4] = 0xa5000000; /* Preserve the bridge latency byte. */
    memory[8][0x0c/4] = 0x00010000; /* Type-1 bridge, not endpoint BAR2 at +0x18. */
    memory[9][0x2000/4] = 0x447514e4;
    memory[9][0x2004/4] = 0x00100000;
    original_endpoint_command = 0x00100000; original_bar0 = 4;
    memory[9][0x2008/4] = 0x02800005;
    memory[9][0x202c/4] = 0x437514e4;
    memory[9][0x2010/4] = 4; memory[9][0x2080/4] = 0x18001000;
    memory[10][0] = 0x14834375; memory[10][1] = 0x48000000;
    memory[10][0xfc/4] = 0x18100000;
    if (mode >= 7) {
        memory[10][0] = 0x10054375; memory[10][1] = 0x58400009;
        memory[10][0xfc/4] = 0x18111000;
    }
    if (mode >= 8) {
        /* Only the fixed target witnesses are relevant to this MMIO fixture;
         * full table semantics are independently checked by test_wifi_erom.py. */
        memset(erom, 0, sizeof(erom));
        erom[0x44/4] = 0x4bf83e01; erom[0x48/4] = 0x0f084411; erom[0x50/4] = 0x18002005;
        erom[0x68/4] = 0x181020c5; erom[0x70/4] = 0x4bf83c01; erom[0x74/4] = 0x40084411;
        erom[0x7c/4] = 0x18003005; erom[0xa0/4] = 0x181030c5; erom[132] = 0xf;
    }
}
static void verify_quiet(void) {
    assert(!(memory[0][0x71c/4] & 1));
    assert(memory[1][0x80/4] == 0 && memory[1][0x84/4] == 1);
    assert(!memory[2][0x20/4] && !memory[2][0x24/4] && !memory[2][0x28/4]);
    assert(!(memory[4][0x2c/4] & 1));
    uint32_t original_lane = scenario >= 8 && scenario <= 11 ?
        (scenario == 9 ? 0x1d82 : 0x1d02) : 0x80000101;
    assert(memory[7][0x1044/4] == 0x8040 && memory[7][0x1050/4] == original_lane);
    assert(memory[4][0x18/4] == 0x12 && memory[4][0xf4/4] == 0x20);
    assert(memory[4][0x1b8/4] == 0x80 && memory[4][0x2c8/4] == 0xaaaa0555);
    assert(strstr(logs, "power probe restore verified"));
    if (strstr(logs, "Gen1 probe begin:"))
        assert(!(memory[4][0xc/4] | memory[4][0x10/4] | memory[4][0x14/4]));
    assert(unmaps == (mode >= 6 ? 11u : mode + 5) && now_us < 1000000 && link_polls <= 500);
    if (mode >= 5) {
        uint32_t expected_control = endpoint_fault == 7 || endpoint_fault == 10 ? 0x80000000 : 0;
        if (endpoint_fault == 16) expected_control = UINT32_MAX;
        assert(atu[1] == expected_control && memory[8][0x900/4] == (endpoint_fault == 8 ? UINT32_MAX : original_viewport));
        assert(memory[8][0x18/4] == 0xa5000000);
    }
    if (mode >= 6) {
        assert(atu0[1] == (chip_fault == 8 || chip_fault == 10 ? 0x80000000u : 0));
        int erom_dirty_command = mode >= 7 && (erom_fault == 4 || erom_fault == 12);
        if (mode >= 8 && (core_fault == 7 || core_fault == 9)) erom_dirty_command = 1;
        if (mode == 9 && tcm_fault == 5) erom_dirty_command = 1;
        assert(memory[9][0x2004/4] == (original_endpoint_command | (chip_fault == 6 || chip_fault == 9 || erom_dirty_command ? 2u : 0)));
        uint32_t expected_bar = chip_fault == 6 || chip_fault == 9 || erom_dirty_command ? 0x14400004u : chip_fault == 11 ? 0 : original_bar0;
        uint32_t expected_window = chip_fault == 6 || chip_fault == 7 || chip_fault == 9 ?
            0x18000000u : chip_fault == 13 ? UINT32_MAX : 0x18001000u;
        if (mode >= 7 && (erom_fault == 4 || erom_fault == 10 || erom_fault == 12)) expected_window = 0x18111000;
        if (mode >= 8 && core_fault == 7) expected_window = 0x18103000;
        if (mode >= 8 && (core_fault == 8 || core_fault == 9)) expected_window = 0x18002000;
        if (mode == 9 && tcm_fault == 5) expected_window = 0x18002000;
        assert(memory[9][0x2010/4] == expected_bar && memory[9][0x2014/4] == (chip_fault == 12 ? 1u : 0));
        assert(memory[9][0x2080/4] == expected_window);
    }
}
int main(void) {
    reset(0, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(strstr(logs, "Gen1 link up:") && strstr(logs, "Gen1 quiesce verified"));
    assert(link_polls == 3 && !(memory[8][4/4] & 4));
    unsigned normal_writes = writes;
    for (unsigned which = 1; which <= 5; which++) {
        reset(which, 0); b2l_wifi_diag_start(); verify_quiet();
        assert(!strstr(logs, "Gen1 link up:"));
        assert(strstr(logs, "Gen1 quiesce verified"));
        if (which == 1) assert(link_polls == 500);
        if (which == 4) assert(link_polls == 2); /* Absolute 500 ms deadline. */
    }
    reset(0, 0); memory[8][0] = 0; b2l_wifi_diag_start(); verify_quiet();
    assert(strstr(logs, "Gen1 link up:")); /* Root identity may not be programmed yet. */
    for (unsigned failure = 1; failure <= 9; failure++) {
        reset(0, failure); b2l_wifi_diag_start();
        assert(!writes && !gen1_reads && maps == failure && unmaps == failure - 1);
    }
    reset(0, 0); memory[4][0x1d0/4] = 0; b2l_wifi_diag_start();
    assert(!gen1_reads && !strstr(logs, "Gen1 probe begin:") && strstr(logs, "Gen1 probe skipped:"));
    verify_quiet();
    reset(0, 0); memory[2][0x20/4] = 2; b2l_wifi_diag_start();
    assert(!gen1_reads && strstr(logs, "Gen1 probe skipped: CLKREQ"));
    assert(memory[2][0x20/4] == 2 && !(memory[0][0x71c/4] & 1));
    assert(!(memory[1][0x84/4] & 32) && unmaps == 9);
    /* A lost write anywhere, including cleanup, must not leave power/reset or
     * root bus mastering enabled. Training requires all actual PHY values. */
    unsigned bits_diagnostic = 0, reset_diagnostic = 0, pci_diagnostic = 0;
    for (unsigned failure = 1; failure <= normal_writes; failure++) {
        reset(0, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        if (strstr(logs, "Gen1 root DBI ID=")) assert(!(memory[8][4/4] & 4));
        if (strstr(logs, "bits mismatch pa=0x13ed0000 off=0xf4 mask=0x11 before=0x20 got=0x20 want=0x11")) {
            bits_diagnostic++;
            assert(strstr(logs, "stage=phy-calibration polls=0 last_ELBI=0"));
        }
        if (strstr(logs, "reset pulse mismatch off=0x288 got=0 want=1")) {
            reset_diagnostic++;
            assert(strstr(logs, "stage=phy-calibration polls=0 last_ELBI=0"));
        }
        if (strstr(logs, "PCI control mismatch off=0x4 mask=0x147 before=0xdead0144 got=0xdead0144 want=0x2")) {
            pci_diagnostic++;
            assert(strstr(logs, "stage=root-policy polls=0 last_ELBI=0"));
        }
    }
    assert(bits_diagnostic && reset_diagnostic && pci_diagnostic);
    /* Replay the exact hardware mismatch, keeping the vendor write of 0x1d0c.
     * A different baseline, another missing bit or all-ones readback must stop. */
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(strstr(logs, "Gen1 link up:") && strstr(logs, "Gen1 quiesce verified"));
    assert(strstr(logs, "observed board readback before=0x1d02 wrote=0x1d0c got=0x1d04"));
    unsigned board_writes = writes;
    for (unsigned failure = 1; failure <= board_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
    }
    for (unsigned fault = 9; fault <= 11; fault++) {
        reset(fault, 0); b2l_wifi_diag_start(); verify_quiet();
        assert(!link_polls && !strstr(logs, "Gen1 root DBI ID="));
        assert(strstr(logs, "PHY SYSREG profile mismatch"));
        assert(strstr(logs, "stage=phy-calibration polls=0") && strstr(logs, "Gen1 quiesce verified"));
    }
    for (unsigned fault = 6; fault <= 7; fault++) {
        reset(fault, 0); b2l_wifi_diag_start();
        assert(strstr(logs, "Gen1 quiesce FAILED") && strstr(logs, "power probe restore verified"));
        assert(!(memory[0][0x71c/4] & 1) && !(memory[1][0x84/4] & 32));
        assert(!memory[2][0x20/4] && !(memory[2][0x24/4] & 4));
        assert(now_us < 1000000 && unmaps == 9 && writes < normal_writes + 20);
    }
    puts("Gen1: exact MMIO boundaries, PHY profile, reset/power ordering, no BME/ATU/endpoint access, deadline, dropped writes and quiescence passed");
    mode = 5;
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(endpoint_reads == 4 && strstr(logs, "endpoint identity verified: 14e4:4475 subsystem 14e4:4375 PCI revision=5 class=0x28000"));
    assert(strstr(logs, "endpoint probe end: stage=complete cleanup=verified"));
    unsigned endpoint_writes = writes;
    for (unsigned failure = 1; failure <= endpoint_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        assert(endpoint_reads <= 4);
    }
    for (unsigned failure = 1; failure <= 10; failure++) {
        reset(8, failure); b2l_wifi_diag_start();
        assert(!writes && !endpoint_reads && maps == failure && unmaps == failure - 1);
    }
    for (unsigned fault = 1; fault <= 19; fault++) {
        reset(8, 0); endpoint_fault = fault;
        if (fault == 7) atu[1] = 0x80000000; /* Existing active region must not be changed. */
        if (fault == 8) memory[8][0x900/4] = UINT32_MAX; /* Unsupported unrolled ATU. */
        if (fault == 16) atu[1] = UINT32_MAX;
        if (fault == 18) memory[8][0x0c/4] = 0;
        b2l_wifi_diag_start(); verify_quiet();
        if (fault == 1 || fault == 2 || fault == 6 || fault == 11 || fault == 14) assert(endpoint_reads == 1);
        if (fault == 3) assert(endpoint_reads == 2);
        if (fault == 13) assert(endpoint_reads == 3);
        if (fault == 4 || fault == 10) assert(endpoint_reads == 4);
        if (fault == 5 || fault == 7 || fault == 8 || fault == 9 || fault == 12 || fault == 15 || fault == 16 || fault == 17 || fault == 18 || fault == 19)
            assert(!endpoint_reads);
        if (fault == 10) {
            assert(strstr(logs, "cleanup=FAILED") && strstr(logs, "Gen1 quiesce FAILED"));
            assert(writes < endpoint_writes + 20);
        } else assert(!strstr(logs, "endpoint identity verified:") && strstr(logs, "Gen1 quiesce verified"));
    }
    reset(8, 0); original_viewport = memory[8][0x900/4] = 0x80000002;
    b2l_wifi_diag_start(); verify_quiet();
    assert(endpoint_reads == 4 && strstr(logs, "endpoint identity verified:"));
    reset(8, 0); atu[0] = atu[2] = atu[3] = atu[4] = atu[5] = atu[6] = UINT32_MAX;
    b2l_wifi_diag_start(); verify_quiet();
    assert(endpoint_reads == 4 && strstr(logs, "endpoint identity verified:"));
    reset(1, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(link_polls == 500 && !endpoint_reads && !atu_enable_write);
    puts("Endpoint: exact read-only CFG0 scope, ATU1/bus guards and cleanup, link/deadline checks, all mapping/dropped-write failures passed");
    mode = 6;
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(chip_reads == 3 && strstr(logs, "chipcommon identity verified: chip=0x4375 revision=3 package=8 interconnect=1"));
    assert(strstr(logs, "chipcommon probe end: stage=complete cleanup=verified"));
    unsigned chip_writes = writes;
    for (unsigned failure = 1; failure <= chip_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        assert(chip_reads <= 3);
    }
    for (unsigned failure = 1; failure <= 11; failure++) {
        reset(8, failure); b2l_wifi_diag_start();
        assert(!writes && !endpoint_reads && !chip_reads && maps == failure && unmaps == failure - 1);
    }
    for (unsigned fault = 1; fault <= 14; fault++) {
        reset(8, 0); chip_fault = fault;
        if (fault == 10) atu0[1] = 0x80000000;
        if (fault == 11) memory[9][0x2010/4] = 0;
        if (fault == 12) memory[9][0x2014/4] = 1;
        if (fault == 13) memory[9][0x2080/4] = UINT32_MAX;
        b2l_wifi_diag_start(); verify_quiet();
        if (fault >= 6 && fault <= 9) {
            assert(strstr(logs, "chipcommon probe end:") && strstr(logs, "cleanup=FAILED"));
            assert(strstr(logs, "Gen1 quiesce FAILED") && strstr(logs, "power probe restore verified"));
            assert(writes < chip_writes + 25);
            assert(chip_reads == (fault == 9 ? 0u : 3u));
        } else {
            assert(!strstr(logs, "chipcommon identity verified:") && strstr(logs, "Gen1 quiesce verified"));
            assert(chip_reads == (fault >= 10 ? 0u : fault == 3 ? 2u : fault == 4 ? 3u : 1u));
        }
    }
    reset(8, 0); original_endpoint_command = memory[9][0x2004/4] = 0xabcd0400;
    original_bar0 = memory[9][0x2010/4] = 0x14400004;
    original_viewport = memory[8][0x900/4] = 0x80000002;
    b2l_wifi_diag_start(); verify_quiet();
    assert(chip_reads == 3 && strstr(logs, "chipcommon identity verified:"));
    puts("Chipcommon: first-page reads, BAR0/window/command and ATU0 cleanup, no BME/RAM/chip writes, map and dropped-write failures passed");
    mode = 7;
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(erom_reads == 7 && strstr(logs, "EROM capture complete: words=7"));
    unsigned erom_writes = writes;
    for (unsigned failure = 1; failure <= erom_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        assert(erom_reads <= 7);
    }
    for (unsigned fault = 1; fault <= 12; fault++) {
        if (fault == 11) continue;
        reset(8, 0); erom_fault = fault;
        if (fault == 1) erom[0] = UINT32_MAX;
        if (fault == 2 || fault == 9) memset(erom, 0, sizeof(erom));
        if (fault == 5) memory[10][0] = 0x10044375;
        if (fault == 6) memory[10][0xfc/4] = 0x18112000;
        if (fault == 7) {
            erom[2] = 0x1800003d; erom[3] = 0xf; /* Untagged address high. */
            erom[4] = 0x2008; erom[5] = 0xf; /* Untagged size high. */
        }
        if (fault == 8) erom[2] = UINT32_MAX;
        if (fault == 9) erom[895] = 0xf;
        b2l_wifi_diag_start(); verify_quiet();
        if (fault == 4 || fault == 10 || fault == 12) {
            assert(strstr(logs, "cleanup=FAILED") && strstr(logs, "Gen1 quiesce FAILED"));
            assert(strstr(logs, "power probe restore verified"));
        } else assert(strstr(logs, "Gen1 quiesce verified"));
        if (fault == 1 || fault == 3 || fault == 4) assert(erom_reads == 1);
        if (fault == 2 || fault == 9) assert(erom_reads == 896);
        if (fault == 5 || fault == 6) assert(!erom_reads && !strstr(logs, "EROM capture begin:"));
        if (fault == 7 || fault == 10 || fault == 12) assert(erom_reads == 7);
        if (fault == 8) assert(erom_reads == 3);
        if (fault == 7 || fault == 9 || fault == 10 || fault == 12) assert(strstr(logs, "EROM capture complete:"));
        else assert(!strstr(logs, "EROM capture complete:"));
        assert(writes < erom_writes + 4000);
    }
    puts("EROM: measured page only, 896-word/deadline bounds, data extensions vs terminators, invalid data and cleanup faults passed");
    mode = 8;
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(wrapper_reads[0] == 3 && wrapper_reads[1] == 3 && r4_cap_reads == 1);
    assert(strstr(logs, "core snapshot complete: wrappers=2 R4_capabilities=read"));
    unsigned core_writes = writes;
    for (unsigned failure = 1; failure <= core_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        assert(wrapper_reads[0] <= 3 && wrapper_reads[1] <= 3 && r4_cap_reads <= 1);
    }
    for (unsigned fault = 1; fault <= 9; fault++) {
        reset(8, 0); core_fault = fault;
        if (fault == 1) wrapper_values[1][0] = 0;
        if (fault == 2) wrapper_values[1][0] = 3;
        if (fault == 3) wrapper_values[1][2] = 1;
        if (fault == 4) wrapper_values[0][0] = UINT32_MAX;
        b2l_wifi_diag_start(); verify_quiet();
        if (fault <= 3) {
            assert(!r4_cap_reads && strstr(logs, "core snapshot complete: wrappers=2 R4_capabilities=skipped"));
        }
        if (fault == 4 || fault == 6 || fault == 7) assert(wrapper_reads[0] == 1 && !wrapper_reads[1] && !r4_cap_reads);
        if (fault >= 7) {
            assert(strstr(logs, "cleanup=FAILED") && strstr(logs, "Gen1 quiesce FAILED"));
            assert(strstr(logs, "power probe restore verified"));
        } else assert(strstr(logs, "Gen1 quiesce verified"));
    }
    static const unsigned witness_offsets[] = { 0x44, 0x48, 0x50, 0x68, 0x70, 0x74, 0x7c, 0xa0 };
    for (unsigned i = 0; i < 8; i++) {
        reset(8, 0); erom[witness_offsets[i]/4] ^= 0x1000; b2l_wifi_diag_start(); verify_quiet();
        assert(!wrapper_reads[0] && !wrapper_reads[1] && !r4_cap_reads);
        assert(strstr(logs, "core snapshot skipped: measured EROM witnesses/count differ"));
    }
    reset(8, 0); erom[132] = 0; erom[133] = 0xf; b2l_wifi_diag_start(); verify_quiet();
    assert(erom_reads == 134 && !wrapper_reads[0] && !strstr(logs, "core snapshot begin:"));
    puts("Core state: measured EROM witnesses, fixed read-only wrappers, gated/reset R4 rejection and dropped-write/cleanup failures passed");
    mode = 9;
    reset(8, 0); b2l_wifi_diag_start(); verify_quiet();
    assert(bank_reads == 13 && bank_writes == 14 && bank_index == 7);
    /* Five 4-KiB banks and eight 128-KiB banks cover both unit-size encodings. */
    assert(strstr(logs, "TCM inventory end: stage=complete banks=13 bytes=1069056 selector_restore=verified"));
    unsigned tcm_writes = writes;
    for (unsigned failure = 1; failure <= tcm_writes; failure++) {
        reset(8, 0); drop_write = failure; b2l_wifi_diag_start(); verify_quiet();
        assert(bank_reads <= 13 && bank_index == 7);
        assert(!strstr(logs, "selector_restore=FAILED"));
    }
    for (unsigned fault = 1; fault <= 11; fault++) {
        reset(8, 0); tcm_fault = fault;
        if (fault == 10) wrapper_values[1][0] = 1; /* Running R4: no selector access. */
        b2l_wifi_diag_start(); verify_quiet();
        if (fault == 1 || (fault >= 8 && fault <= 10)) assert(!bank_writes && !bank_reads);
        if (fault == 2) assert(bank_reads == 1 && bank_index == 7);
        if (fault == 3) assert(bank_reads == 6 && bank_index == 7);
        if (fault == 4) assert(bank_reads == 1 && bank_index == 7);
        if (fault == 5) assert(bank_reads == 1 && bank_index == 0);
        if (fault == 6) assert(bank_reads == 13 && bank_index == 12 && bank_writes == 16);
        if (fault == 7) assert(!bank_reads && bank_writes == 2 && bank_index == 7);
        if (fault == 11) assert(!bank_reads && bank_writes == 2 && bank_index == 7);
        if (fault == 5 || fault == 6) {
            assert(strstr(logs, "selector_restore=FAILED") && strstr(logs, "cleanup=FAILED"));
            assert(strstr(logs, "power probe restore verified"));
        } else assert(bank_index == 7 && strstr(logs, "Gen1 quiesce verified"));
    }
    for (unsigned i = 0; i < 8; i++) {
        reset(8, 0); erom[witness_offsets[i]/4] ^= 0x1000; b2l_wifi_diag_start(); verify_quiet();
        assert(!wrapper_reads[0] && !bank_reads && !bank_writes);
    }
    reset(8, 0); erom[132] = 0; erom[133] = 0xf; b2l_wifi_diag_start(); verify_quiet();
    assert(!wrapper_reads[0] && !bank_reads && !bank_writes);
    /* Same clock/forced-clock/reset guards also apply to the mutation mode. */
    for (unsigned fault = 1; fault <= 3; fault++) {
        reset(8, 0);
        if (fault == 1) wrapper_values[1][0] = 0;
        if (fault == 2) wrapper_values[1][0] = 0x23;
        if (fault == 3) wrapper_values[1][2] = 1;
        b2l_wifi_diag_start(); verify_quiet();
        assert(!bank_reads && !bank_writes && strstr(logs, "TCM inventory skipped:"));
    }
    puts("TCM inventory: halted measured R4, selector-only writes, bounded 13-bank sizing, both units and selector restoration/fault guards passed");
}
'''

with tempfile.TemporaryDirectory(prefix='b2l-wifi-gen1-') as temporary:
    path = Path(temporary) / 'gen1.c'
    binary = Path(temporary) / 'gen1-test'
    path.write_text(pre + source + post)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer', '-I', str(repo / 'xnu-overlay/osfmk/arm64'),
        str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
