import struct
import unittest

from l2_monitor.client_catalog import CachedMemory, ClientCatalog, table_entries


class Memory:
    def __init__(self):
        self.data = bytearray(16384)
        self.reads = 0
    def read(self, address, size):
        self.reads += 1
        return bytes(self.data[address:address + size])


class ClientCatalogTests(unittest.TestCase):
    def test_database_includes_unowned_items_and_exact_skill_levels(self):
        catalog = ClientCatalog()
        self.assertEqual(catalog.item_name(1061), 'Greater Healing Potion')
        self.assertEqual(catalog.skill_name(1204, 1), 'Wind Walk')
        self.assertEqual(catalog.skill_name(1204, 999999), '')
        self.assertGreater(catalog.summary()['items'], 28000)
        self.assertGreater(catalog.summary()['skills'], 84000)
        result = catalog.query('skills', 'Might')
        self.assertTrue(any(row['id'] == 1068 for row in result['rows']))

    def test_pagination_and_description_search_cover_whole_catalog(self):
        catalog = ClientCatalog()
        catalog.replace(dict(items=[dict(id=i, name=str(i)) for i in range(1005)],
                             skills=[dict(id=8, level=1, name='A', description='special description')]))
        self.assertEqual([r['id'] for r in catalog.query(offset=1000)['rows']], list(range(1000, 1005)))
        self.assertEqual(catalog.query('skills', 'special')['total'], 1)
        self.assertEqual(catalog.query(search='unmatched')['total'], 0)
        for args in [('invalid', '', 0, 1), ('items', '', -1, 1), ('items', '', 0, 10001)]:
            with self.assertRaises(ValueError):
                catalog.query(*args)

    def test_cached_reads_preserve_cross_page_bytes(self):
        memory = Memory()
        memory.data[4090:4100] = b'abcdefghij'
        cached = CachedMemory(memory)
        self.assertEqual(cached.read(4090, 10), b'abcdefghij')
        self.assertEqual(cached.read(4092, 7), b'cdefghi')
        self.assertEqual(memory.reads, 2)

    def test_table_validation_prevents_unbounded_reads(self):
        memory = Memory()
        struct.pack_into('<5I', memory.data, 0, 100, 1, 1, 200, 8)
        struct.pack_into('<3I', memory.data, 100, 0xffffffff, 1061, 500)
        self.assertEqual(table_entries(memory, 0), [(1061, 500)])
        struct.pack_into('<I', memory.data, 4, 2000001)
        with self.assertRaises(ValueError):
            table_entries(memory, 0)
