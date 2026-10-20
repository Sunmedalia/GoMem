import unittest
from verify_lsof import decode_time


class InodeTimestampOracleTests(unittest.TestCase):
    def test_exact_seconds_and_fraction(self):
        self.assertEqual(decode_time(0, 0), '1970-01-01T00:00:00Z')
        self.assertEqual(decode_time(-1, 1), '1969-12-31T23:59:59.000000001Z')
        self.assertEqual(decode_time(1700000000, 123456789), '2023-11-14T22:13:20.123456789Z')
        self.assertEqual(decode_time(253402300799, 999999999), '9999-12-31T23:59:59.999999999Z')
        self.assertEqual(decode_time(-62135596800, 0), '0001-01-01T00:00:00Z')

    def test_invalid_seconds_and_nanoseconds(self):
        for sec, ns in ((0, -1), (1, 1000000000), (253402300800, 0), (-62135596801, 0)):
            with self.assertRaises(ValueError):
                decode_time(sec, ns)

class AnonymousFieldOracleTests(unittest.TestCase):
    def test_union_field_offset(self):
        from verify_lsof import resolve_field
        table = {'user_types': {'inode': {'fields': {'anonymous': {'offset': 72, 'anonymous': True, 'type': {'kind': 'union', 'name': 'links'}}}}, 'links': {'fields': {'i_nlink': {'offset': 0, 'type': {'kind': 'base', 'name': 'u32'}}}}}}
        self.assertEqual(resolve_field(table, 'inode', 'i_nlink')['offset'], 72)
        with self.assertRaises(KeyError):
            resolve_field(table, 'inode', 'not_present')

    def test_cyclic_anonymous_types_are_rejected(self):
        from verify_lsof import resolve_field
        table = {'user_types': {'inode': {'fields': {'self': {'offset': 0, 'anonymous': True, 'type': {'kind': 'struct', 'name': 'inode'}}}}}}
        with self.assertRaises(ValueError):
            resolve_field(table, 'inode', 'missing')


if __name__ == '__main__':
    unittest.main()
