import unittest
from pathlib import Path
import tempfile

from PySide6.QtWidgets import QApplication
from l2_monitor.client_icons import ClientIcons


class ClientIconsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self):
        self.icons = ClientIcons(capacity=3)

    def tearDown(self):
        self.icons.close()

    def test_potion_mapping_uses_client_reference(self):
        self.assertEqual(self.icons.reference('item', 1061), 'icon.etc_potion_scarlet_i00')
        image = self.icons.icon('item', 1061)
        self.assertFalse(image.isNull())
        self.assertEqual(image.pixmap(32, 32).size().width(), 32)

    def test_newbie_buff_shares_its_real_skill_image(self):
        self.assertEqual(self.icons.reference('skill', 4322, 1), self.icons.reference('skill', 1204, 2))
        self.assertEqual(self.icons.icon('skill', 4322, 1).cacheKey(), self.icons.icon('skill', 1204, 2).cacheKey())

    def test_unresolved_entries_remain_without_invented_icon(self):
        self.assertIsNone(self.icons.icon('item', 99999999))
        self.assertIsNone(self.icons.icon('skill', 99999999, 1))
        self.assertIsNone(self.icons.reference('unknown', 1204, 2))

    def test_image_cache_is_bounded_and_survives_eviction(self):
        for item in (57, 1061, 2, 16, 1060):
            image = self.icons.icon('item', item)
            self.assertFalse(image.isNull())
        self.assertLessEqual(len(self.icons.cache), 3)
        self.assertFalse(self.icons.icon('item', 57).isNull())

    def test_missing_asset_bundle_keeps_names_usable(self):
        with tempfile.TemporaryDirectory() as folder:
            icons = ClientIcons(Path(folder) / 'absent.zip')
            self.assertIsNone(icons.icon('item', 1061))
            icons.close()
