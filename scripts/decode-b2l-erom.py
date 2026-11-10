#!/usr/bin/env python3
"""Validate a mode-7 console capture and decode AI EROM descriptors on the host.

Format: pinned Samsung bcmdhd_101_16/include/aidmp.h and aiutils.c, revision
a412cfaf86b980ce35cae96a35f678c8ea551575. This tool never accesses a device.
"""
import argparse
import json
from pathlib import Path
import re

MAX_WORDS = 0xe00 // 4
NAMES = {0x800: 'chipcommon', 0x812: 'D11 MAC', 0x827: 'PMU', 0x83c: 'PCIe2',
         0x83e: 'ARM Cortex-R4', 0x840: 'GCI', 0x841: 'SR', 0x844: 'M2M DMA',
         0x849: 'system memory'}


class EromError(ValueError):
    pass


def extract(text):
    words = []
    begun = complete = False
    count = None
    for line in text.splitlines():
        if line.startswith('B2L WIFI: EROM capture begin:'):
            if begun:
                raise EromError('More than one capture; supply one console epoch')
            begun = True
        elif line.startswith('B2L WIFI: EROM +'):
            match = re.fullmatch(r'B2L WIFI: EROM \+(0x[0-9a-fA-F]+|0) raw=(0x[0-9a-fA-F]+|0)', line)
            if not begun or complete or not match:
                raise EromError('Unordered or malformed EROM word line')
            offset, value = (int(s, 0) for s in match.groups())
            if offset != len(words) * 4 or len(words) >= MAX_WORDS:
                raise EromError('Missing, repeated or out-of-bounds ROM offset')
            if not 0 <= value < 0xffffffff:
                raise EromError('Invalid ROM word')
            words.append(value)
        elif line.startswith('B2L WIFI: EROM capture complete:'):
            match = re.match(r'B2L WIFI: EROM capture complete: words=(\d+);', line)
            if not begun or complete or not match:
                raise EromError('Malformed or repeated capture completion')
            count = int(match.group(1))
            complete = True
        elif line.startswith(('B2L WIFI: EROM capture stopped:', 'B2L WIFI: EROM capture skipped:')):
            raise EromError('The device did not complete the capture')
    if not complete or not words or count != len(words):
        raise EromError('Incomplete capture or mismatched completion count')
    return words


def decode(words):
    if not words or len(words) > MAX_WORDS or any(type(v) is not int or not 0 <= v < 0xffffffff for v in words):
        raise EromError('Invalid bounded word array')
    cursor = 0
    components = []
    instances = {}

    def raw():
        nonlocal cursor
        if cursor >= len(words):
            raise EromError('Truncated descriptor or missing terminator')
        value = words[cursor]
        cursor += 1
        return value

    def skip_padding():
        nonlocal cursor
        while cursor < len(words) and not words[cursor] & 1:
            cursor += 1

    while True:
        skip_padding()
        offset = cursor * 4
        cia = raw()
        if cia == 0xf:
            if cursor != len(words) or not components:
                raise EromError('Trailing words or empty component table')
            return {'word_count': len(words), 'component_count': len(components),
                    'terminator_offset': offset, 'components': components}
        cib = raw()
        if cia & 0xf != 1 or cib & 0xf != 1:
            raise EromError(f'Invalid component identity pair at {offset:#x}')
        cid, manufacturer = (cia >> 8) & 0xfff, (cia >> 20) & 0xfff
        nmp, nsp, nmw, nsw = (cib >> 4) & 31, (cib >> 9) & 31, (cib >> 14) & 31, (cib >> 19) & 31
        instance = instances.get((manufacturer, cid), 0)
        instances[(manufacturer, cid)] = instance + 1
        component = dict(erom_offset=offset, manufacturer=manufacturer, core_id=cid,
                         instance=instance, name=NAMES.get(cid, 'unclassified component') if manufacturer == 0x4bf else 'unclassified component',
                         component_class=(cia >> 4) & 15, revision=(cib >> 24) & 255,
                         declared_master_ports=nmp, declared_slave_ports=nsp,
                         declared_master_wrappers=nmw, declared_slave_wrappers=nsw,
                         master_ports=[], addresses=[])
        while True:
            skip_padding()
            if cursor >= len(words):
                raise EromError('Missing terminator')
            entry = words[cursor]
            if entry == 0xf or entry & 0xe == 0:
                break
            entry_offset = cursor * 4
            raw()
            if entry & 0xe == 2:
                component['master_ports'].append({'port': (entry >> 4) & 15, 'unit': (entry >> 8) & 255})
                continue
            if entry & 6 != 4:
                raise EromError(f'Unsupported descriptor tag at {entry_offset:#x}')
            address = entry & 0xfffff000
            if entry & 8:
                address |= raw() << 32
            encoding = (entry >> 4) & 3
            if encoding == 3:
                size_word = raw()
                size = size_word & 0xfffff000
                if size_word & 8:
                    size |= raw() << 32
            else:
                size = 0x1000 << encoding
            if not size or address + size > 1 << 64:
                raise EromError('Invalid size or overflowing address range')
            component['addresses'].append(dict(erom_offset=entry_offset, address=address, size=size,
                                              port=(entry >> 8) & 15,
                                              kind=['slave', 'bridge', 'slave_wrapper', 'master_wrapper'][(entry >> 6) & 3]))
        if [p['port'] for p in component['master_ports']] != list(range(nmp)):
            raise EromError(f'Master-port count/order mismatch at {offset:#x}')
        for kind, ports in [('master_wrapper', list(range(nmw))),
                            ('slave_wrapper', list(range(0 if nsp <= 1 else 1, (0 if nsp <= 1 else 1) + nsw)))]:
            descriptors = [a for a in component['addresses'] if a['kind'] == kind]
            if [a['port'] for a in descriptors] != ports or any(a['size'] != 0x1000 for a in descriptors):
                raise EromError(f'Wrapper count/order/size mismatch at {offset:#x}')
        slave_ports = {a['port'] for a in component['addresses'] if a['kind'] in ('slave', 'bridge')}
        if slave_ports != set(range(nsp)):
            raise EromError(f'Slave-port coverage mismatch at {offset:#x}')
        components.append(component)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('console', type=Path)
    args = parser.parse_args()
    try:
        result = decode(extract(args.console.read_text()))
    except EromError as error:
        parser.exit(1, f'EROM rejected: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
