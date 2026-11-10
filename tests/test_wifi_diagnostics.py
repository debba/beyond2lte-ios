#!/usr/bin/env python3
"""Exercise actual Wi-Fi diagnostic code, MMIO boundaries and recovery guards."""
import importlib.util
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wifi_probe', REPO / 'scripts/probe-b2l-wifi.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RecoveryTests(unittest.TestCase):
    def test_pci_ids(self):
        data = ('DEVICE 0000:01:00.0\nATTRIBUTE vendor\n0x14e4\n'
                'ATTRIBUTE device\n0x4475\nATTRIBUTE revision\n0x01\n'
                'ATTRIBUTE resource\n00000000 00000000 00000000\nDRIVER\n../bcmdhd\n')
        self.assertEqual(probe.pci_ids(data), [{'bdf': '0000:01:00.0', 'vendor': '0x14e4',
                                              'device': '0x4475', 'revision': '0x01'}])
        self.assertEqual(probe.pci_ids(''), [])
        for bad in ('DEVICE ../../other\n', 'DEVICE 0000:01:00.0\nATTRIBUTE vendor\ngarbage\n'):
            with self.assertRaises(probe.ProbeError):
                probe.pci_ids(bad)

    def test_identity_fails_before_hardware_reads(self):
        class Fake(probe.Recovery):
            def call(self, *args):
                calls.append(args)
                answers = {
                    ('devices',): b'List of devices attached\nTEST\trecovery\n',
                    ('get-state',): b'recovery\n',
                    ('shell', '-T', 'getprop ro.product.device'): b'otherphone\n',
                }
                return answers[args]
        calls = []
        with self.assertRaisesRegex(probe.ProbeError, 'not beyond2lte'):
            Fake('adb', None)
        self.assertEqual(len(calls), 3)
        self.assertFalse(any('sys/' in str(call) for call in calls))

    def test_ambiguous_or_nonrecovery_device(self):
        class Fake(probe.Recovery):
            def call(self, *args):
                self.outer.assertEqual(args, ('devices',))
                return response
        Fake.outer = self
        for response in (b'List of devices attached\n',
                         b'List of devices attached\nA\tdevice\n',
                         b'List of devices attached\nA\trecovery\nB\trecovery\n'):
            with self.assertRaises(probe.ProbeError):
                Fake('adb', None)

    def test_private_capture_and_no_overwrite(self):
        class Fake:
            def shell(self, command):
                commands.append(command)
                return b''
        commands = []
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'capture'
            receipt = probe.collect(Fake(), output)
            self.assertFalse(receipt['device_writes'])
            self.assertFalse(receipt['pci_config_transactions'])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for file in output.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(commands, [probe.PCI_INVENTORY, probe.PLATFORM_INVENTORY,
                                        probe.GPIO_INVENTORY, 'uname -a'])
            with self.assertRaises(FileExistsError):
                probe.collect(Fake(), output)


def test_kernel():
    source = (REPO / 'xnu-overlay/osfmk/arm64/b2l_wifi_diag.c').read_text()
    source = '\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
    original = 'return *(volatile const uint32_t *)(region->mapped + offset);'
    if source.count(original) != 1:
        raise RuntimeError('Diagnostic MMIO accessor changed; update boundary fixture.')
    source = source.replace(original, 'return host_read(region->mapped, offset);')
    original_write = '''    *(volatile uint32_t *)(region->mapped + offset) = value;
    __asm__ volatile ("dsb sy" ::: "memory");'''
    if source.count(original_write) != 1:
        raise RuntimeError('Diagnostic MMIO writer changed; update boundary fixture.')
    source = source.replace(original_write, '    host_write(region->mapped, offset, value);')
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
static _Alignas(16384) uint32_t memory[5][4096];
static const uintptr_t physical[] = {0x15860000, 0x10430000, 0x13c40000, 0x13c00000, 0x13ed0000};
static unsigned maps, unmapped, reads, fail_map;
static unsigned writes, drop_write, permanent_drop, delays_ms, poison_once_after_write;
static unsigned controller_reads;
static int mode;
static char logs[8192];
static unsigned log_size;
static uint64_t host_time_us;
static uint64_t mach_absolute_time(void) { return host_time_us; }
static void clock_interval_to_deadline(unsigned amount, unsigned unit, uint64_t *deadline) {
    *deadline = host_time_us + (uint64_t)amount * unit / 1000;
}
static void delay(unsigned us) { host_time_us += us; }
static void delay_for_interval(unsigned amount, unsigned unit) {
    assert(unit == NSEC_PER_MSEC && (amount == 200 || amount == 20 || amount == 1));
    delays_ms += amount;
    host_time_us += amount * 1000;
}
static void b2l_early_trace(const char *fmt, ...) {
    va_list args; va_start(args, fmt);
    int n = vsnprintf(logs + log_size, sizeof(logs) - log_size, fmt, args);
    va_end(args); assert(n >= 0 && (unsigned)n < sizeof(logs) - log_size);
    log_size += (unsigned)n;
}
static int PE_parse_boot_argn(const char *name, void *value, unsigned size) {
    assert(!strcmp(name, "b2l_wifi_diag") && size == 4);
    if (mode == -1) return 0;
    *(uint32_t *)value = (uint32_t)mode; return 1;
}
static uintptr_t ml_io_map_unmappable(uintptr_t address, unsigned long size, unsigned flags) {
    assert(maps < (mode == 3 ? 5u : 4u) && address == physical[maps] && size == 0x4000 && flags == VM_WIMG_IO);
    unsigned i = maps++;
    return maps == fail_map ? 0 : (uintptr_t)memory[i];
}
static void ml_io_unmap(uintptr_t address, unsigned long size) {
    unsigned successful = maps - (fail_map && fail_map <= maps ? 1 : 0);
    assert(unmapped < successful && size == 0x4000);
    assert(address == (uintptr_t)memory[successful - ++unmapped]);
}
static uint32_t host_read(uintptr_t address, unsigned offset) {
    assert(maps == (mode == 3 ? 5u : 4u) && !fail_map && !unmapped && !(offset & 3));
    for (unsigned i = 0; i < 5; i++) if (address == (uintptr_t)memory[i]) {
        int allowed = (i == 0 && offset == 0x71c) ||
            (i == 1 && (offset == 0x80 || offset == 0x84)) ||
            (i == 2 && (offset == 0x20 || offset == 0x24)) ||
            (i == 3 && ((offset >= 0x2030 && offset <= 0x2044) ||
                        (offset >= 0x3034 && offset <= 0x3044))) ||
            (i == 4 && (offset == 0x2c || offset == 0x74 || offset == 0x1d0 ||
                        offset == 0x288 || offset == 0x28c || offset == 0x290));
        assert(allowed); reads++;
        if (i == 4) {
            assert(mode == 3 && delays_ms >= 201);
            assert(memory[0][0x71c/4] & 1);
            assert(((memory[1][0x80/4] >> 20) & 15) == 1 && (memory[1][0x84/4] & 32));
            assert(((memory[2][0x20/4] >> 8) & 15) == 1 && !(memory[2][0x24/4] & 4));
            controller_reads++;
        }
        if (poison_once_after_write && writes == poison_once_after_write) {
            poison_once_after_write = 0; return UINT32_MAX;
        }
        return memory[i][offset / 4];
    }
    assert(0); return 0;
}
static void host_write(uintptr_t address, unsigned offset, uint32_t value) {
    assert(maps == (mode == 3 ? 5u : 4u) && !fail_map && !unmapped && !(offset & 3));
    for (unsigned i = 0; i < 3; i++) if (address == (uintptr_t)memory[i]) {
        uint32_t mask = 0;
        if (i == 0 && offset == 0x71c) mask = 1;
        if (i == 1 && offset == 0x80) mask = 15u << 20;
        if (i == 1 && offset == 0x84) mask = 1u << 5;
        if (i == 2 && offset == 0x20) mask = 15u << 8;
        if (i == 2 && offset == 0x24) mask = 1u << 2;
        assert(mask && !((memory[i][offset / 4] ^ value) & ~mask));
        writes++;
        if (writes != drop_write && !(permanent_drop && writes >= permanent_drop))
            memory[i][offset / 4] = value;
        return;
    }
    assert(0); /* No controller or clock writes. */
}
'''
    post = r'''
static void reset(int requested, unsigned fail) {
    mode = requested; fail_map = fail; maps = unmapped = reads = log_size = 0;
    writes = drop_write = permanent_drop = delays_ms = poison_once_after_write = controller_reads = 0;
    memset(memory, 0, sizeof(memory)); memset(logs, 0, sizeof(logs));
}
int main(void) {
    const int disabled[] = {-1, 0, 7, 8, -2};
    for (unsigned i = 0; i < sizeof(disabled)/sizeof(disabled[0]); i++) {
        reset(disabled[i], 0); b2l_wifi_diag_start();
        assert(!maps && !reads && !writes && !unmapped && strstr(logs, "disabled"));
    }
    for (unsigned i = 1; i <= 4; i++) {
        reset(1, i); b2l_wifi_diag_start();
        assert(maps == i && unmapped == i - 1 && !reads && !writes && strstr(logs, "map failed"));
    }
    reset(1, 0);
    memory[0][0x71c/4] = 1;
    memory[1][0x80/4] = 1u << 20; memory[1][0x84/4] = 1u << 5;
    memory[2][0x20/4] = (1u << 8) | 2u; memory[2][0x24/4] = 5;
    uint32_t before[5][4096]; memcpy(before, memory, sizeof(before));
    b2l_wifi_diag_start();
    assert(maps == 4 && unmapped == 4 && reads == 16 && !writes && !memcmp(before, memory, sizeof(before)));
    assert(strstr(logs, "isolation_bypass=1; WLAN_REG_ON function=1 level=1"));
    assert(strstr(logs, "PERST function=1 level=1; CLKREQ function=2 level=1"));
    assert(strstr(logs, "Wi-Fi remain unprobed"));
    reset(1, 0); memory[0][0x71c/4] = UINT32_MAX; b2l_wifi_diag_start();
    assert(reads == 5 && unmapped == 4 && strstr(logs, "undecoded"));
    assert(!strstr(logs, "isolation_bypass="));
    reset(1, 0); b2l_wifi_diag_start();
    assert(strstr(logs, "isolation_bypass=0") && reads == 16 && unmapped == 4);
    puts("Wi-Fi snapshot: no controller access, no mode-1 mutations, mode gates and mapping cleanup passed");
    for (unsigned fault = 0; fault <= 8; fault++) {
        reset(2, 0);
        /* Non-owned pins and PMU fields must survive both success and failure. */
        memory[0][0x71c/4] = 0x40;
        memory[1][0x80/4] = 0xa0000001; memory[1][0x84/4] = 0x41;
        memory[2][0x20/4] = 0x2001; memory[2][0x24/4] = 0x81;
        for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
        for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
        memcpy(before, memory, sizeof(before)); drop_write = fault;
        b2l_wifi_diag_start();
        assert(unmapped == 4 && !memcmp(before, memory, sizeof(before)));
        assert(strstr(logs, "power probe restore verified"));
        if (!fault) assert(writes == 8 && delays_ms == 201 && strstr(logs, "power probe readback passed"));
        if (fault >= 1 && fault <= 4) assert(strstr(logs, "power probe readback failed"));
    }
    for (unsigned changed = 0; changed < 5; changed++) {
        reset(2, 0);
        for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
        for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
        switch (changed) {
        case 0: memory[0][0x71c/4] = 1; break;
        case 1: memory[1][0x80/4] = 1u << 20; break;
        case 2: memory[2][0x24/4] = 4; break;
        case 3: memory[3][0x203c/4] = 0; break;
        case 4: memory[3][0x3034/4] = 0; break;
        }
        b2l_wifi_diag_start();
        assert(!writes && !delays_ms && unmapped == 4 && strstr(logs, "power probe skipped"));
    }
    reset(2, 0);
    for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
    for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
    memcpy(before, memory, sizeof(before)); poison_once_after_write = 3;
    b2l_wifi_diag_start();
    assert(!memcmp(before, memory, sizeof(before)) && strstr(logs, "power probe readback failed"));
    assert(strstr(logs, "power probe restore verified"));
    reset(2, 0);
    for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
    for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
    permanent_drop = 5; b2l_wifi_diag_start();
    assert(unmapped == 4 && strstr(logs, "power probe restore FAILED"));
    assert(writes <= 20 && delays_ms <= 220); /* Failed cleanup is bounded and explicit. */
    puts("Wi-Fi power probe: owned-bit writes, failure rollback, busy-state guards and bounded cleanup passed");
    for (unsigned scenario = 0; scenario < 6; scenario++) {
        reset(3, 0);
        for (unsigned off = 0x2030; off <= 0x2044; off += 4) memory[3][off/4] = 0x200000;
        for (unsigned off = 0x3034; off <= 0x3044; off += 4) memory[3][off/4] = 0x3f0002;
        if (scenario == 1) memory[4][0x2c/4] = UINT32_MAX;
        if (scenario == 2) memory[4][0x1d0/4] = UINT32_MAX;
        if (scenario == 3) drop_write = 3;
        if (scenario == 4) memory[3][0x203c/4] = 0;
        if (scenario == 5) fail_map = 5;
        memcpy(before, memory, sizeof(before));
        b2l_wifi_diag_start();
        assert(!memcmp(before, memory, sizeof(before)));
        assert(maps == 5 && unmapped == (scenario == 5 ? 4u : 5u));
        if (!scenario) assert(controller_reads == 6 && writes == 8 && strstr(logs, "ELBI snapshot complete"));
        if (scenario == 1 || scenario == 2) {
            assert(controller_reads == (scenario == 1 ? 1u : 3u));
            assert(strstr(logs, "ELBI snapshot failed") && !strstr(logs, "ELBI snapshot complete"));
        }
        if (scenario >= 3) assert(!controller_reads);
        if (scenario >= 4) assert(!writes);
        if (scenario < 4) assert(strstr(logs, "power probe restore verified"));
    }
    puts("ELBI snapshot: powered/reset prerequisites, fixed read allowlist, no controller writes and failure cleanup passed");
}
'''
    with tempfile.TemporaryDirectory(prefix='b2l-wifi-') as temporary:
        path = Path(temporary) / 'wifi.c'
        path.write_text(pre + source + post)
        binary = Path(temporary) / 'wifi-test'
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                   '-I', str(REPO / 'xnu-overlay/osfmk/arm64'),
                                   str(path), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    test_kernel()
    unittest.main()
