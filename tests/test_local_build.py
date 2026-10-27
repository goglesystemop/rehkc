"""Local build labels cannot collide with an immutable published version."""
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('rehkc_builder',Path(__file__).resolve().parents[1]/'packaging/build_release.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

class LocalBuild(unittest.TestCase):
    def test_release_version_is_preserved_without_a_label(self):
        self.assertEqual(builder.local_version('0.3.0',None),'0.3.0')
    def test_local_version_has_a_distinct_immutable_directory(self):
        a=builder.local_version('0.3.0','dev.20261027.1');b=builder.local_version('0.3.0','dev.20261027.2')
        self.assertEqual(a,'0.3.0-dev.20261027.1');self.assertNotEqual(a,b);self.assertNotEqual(a,'0.3.0')
    def test_unsafe_labels_are_rejected_before_building(self):
        for label in ('','../main','dev/name','dev\nmain','dev$HOME','dev..one','-dev','DEV','a'*49):
            with self.subTest(label=label),self.assertRaises(ValueError):builder.local_version('0.3.0',label)
    def test_dotted_and_hyphenated_labels_are_supported(self):
        self.assertEqual(builder.local_version('0.3.0','dev-cache.2'),'0.3.0-dev-cache.2')

if __name__=='__main__':unittest.main(verbosity=2)
