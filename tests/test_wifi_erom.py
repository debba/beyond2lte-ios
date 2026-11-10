#!/usr/bin/env python3
"""Check host EROM decoding with independent synthetic descriptor streams."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('erom', Path(__file__).resolve().parents[1] / 'scripts/decode-b2l-erom.py')
erom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(erom)


def console(words):
    return '\n'.join(['B2L WIFI: EROM capture begin: synthetic fixture'] +
                     [f'B2L WIFI: EROM +{i * 4:#x} raw={v:#x}' for i, v in enumerate(words)] +
                     [f'B2L WIFI: EROM capture complete: words={len(words)}; raw table only'])


class EromTests(unittest.TestCase):
    def test_core_ports_and_wrappers(self):
        # Core 0x83e, revision 15, one master, one slave, one master wrapper.
        words = [0x4bf83e01, 0x0f004211, 0x403, 0x18002005, 0x181020c5, 0xf]
        result = erom.decode(erom.extract(console(words)))
        self.assertEqual(result['word_count'], 6)
        self.assertEqual(result['terminator_offset'], 20)
        core = result['components'][0]
        self.assertEqual((core['core_id'], core['revision']), (0x83e, 15))
        self.assertEqual(core['master_ports'], [{'port': 0, 'unit': 4}])
        self.assertEqual([(a['address'], a['size'], a['kind']) for a in core['addresses']],
                         [(0x18002000, 4096, 'slave'), (0x18102000, 4096, 'master_wrapper')])

    def test_untagged_terminator_values_in_extensions(self):
        words = [0x4bf80001, 0x01000201, 0x1800003d, 0xf, 0x2008, 0xf, 0xf]
        result = erom.decode(erom.extract(console(words)))
        address = result['components'][0]['addresses'][0]
        self.assertEqual(address['address'], 0xf18000000)
        self.assertEqual(address['size'], 0xf00002000)
        self.assertEqual(result['terminator_offset'], 24)

    def test_multiple_instances_and_zero_based_memory(self):
        words = [0x4bf83e01, 0x01000201, 0x35, 0x150000,
                 0x4bf83e01, 0x02000201, 0x170035, 0x190000, 0xf]
        cores = erom.decode(words)['components']
        self.assertEqual([c['instance'] for c in cores], [0, 1])
        self.assertEqual(cores[0]['addresses'][0]['address'], 0)
        self.assertEqual(cores[1]['addresses'][0]['size'], 0x190000)

    def test_capture_integrity(self):
        good = console([0x4bf80001, 0x01000201, 0x18000005, 0xf])
        for bad in [good.replace('+0x4 ', '+0x8 ', 1), good.replace('words=4;', 'words=5;'),
                    good + '\nB2L WIFI: EROM +0x10 raw=0',
                    good + '\nB2L WIFI: EROM capture begin: second',
                    good + '\nB2L WIFI: EROM capture stopped: failure',
                    good.replace('raw=0xf', 'raw=0xffffffff'), good.split('B2L WIFI: EROM capture complete:')[0]]:
            with self.subTest(bad=bad), self.assertRaises(erom.EromError):
                erom.extract(bad)

    def test_malformed_tables_are_rejected(self):
        good = [0x4bf83e01, 0x0f004211, 0x403, 0x18002005, 0x181020c5, 0xf]
        variants = [[], [0xf], good[:-1], good + [0], good[:4] + [0xf],
                    [good[0], good[1] & ~1] + good[2:],  # Invalid CIB.
                    [good[0], good[1], 0x413] + good[3:],  # Wrong master port.
                    [good[0], (good[1] & ~0x3e00) | 0x400] + good[2:],  # Missing slave port.
                    good[:4] + [0x181020d5, 0xf],  # Wrapper larger than 4 KiB.
                    [0x4bf80001, 0x01000201, 0x1800003d],  # Missing high address/size.
                    [0x4bf80001, 0x01000201, 0xfffff03d, 0xfffffffe, 0xfffff008, 0xfffffffe, 0xf]]
        for words in variants:
            with self.subTest(words=words), self.assertRaises(erom.EromError):
                erom.decode(words)

    def test_invalid_padding_and_non_broadcom_name(self):
        core = erom.decode([0, 0x43b80001, 0x01000201, 0x18000005, 0, 0xf])['components'][0]
        self.assertEqual(core['manufacturer'], 0x43b)
        self.assertEqual(core['name'], 'unclassified component')


if __name__ == '__main__':
    unittest.main()
