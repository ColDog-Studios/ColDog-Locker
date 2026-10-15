"""Validate dependency inventory generation without checked-in NuGet locks."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    'release_manifest', Path(__file__).resolve().parents[1] / 'release_manifest.py')
release_manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_manifest)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        (self.root / 'packaging').mkdir()
        catalog = {
            'schemaVersion': 2,
            'projects': ['Service/Service.csproj', 'Gui/Gui.csproj'],
            'components': [{'name': 'Example', 'license': 'MIT', 'scope': 'runtime'}],
        }
        (self.root / 'packaging/third-party-components.json').write_text(json.dumps(catalog))
        self.write_assets('Service', '1.0.0', 'first-hash')
        self.write_assets('Gui', '1.0.0', 'first-hash')

    def write_assets(self, project, version, sha512, extra=None):
        directory = self.root / project / 'obj'
        directory.mkdir(parents=True, exist_ok=True)
        libraries = {
            f'Example/{version}': {'type': 'package', 'sha512': sha512},
            'ProjectReference/1.0.0': {'type': 'project'},
        }
        libraries.update(extra or {})
        (directory / 'project.assets.json').write_text(json.dumps({'libraries': libraries}))

    def test_version_updates_need_no_catalog_edit_and_record_restored_hashes(self):
        self.write_assets('Service', '2.1.0', 'updated-hash')
        self.write_assets('Gui', '2.1.0', 'updated-hash')
        _, inventory = release_manifest.load_third_party_inventory(self.root)
        self.assertEqual([{
            'name': 'Example', 'license': 'MIT', 'scope': 'runtime',
            'version': '2.1.0', 'sha512': 'updated-hash',
        }], inventory['components'])

    def test_new_dependencies_require_license_review(self):
        self.write_assets('Gui', '1.0.0', 'first-hash', {
            'Unknown/1.0.0': {'type': 'package', 'sha512': 'unknown-hash'},
        })
        with self.assertRaisesRegex(SystemExit, 'license review.*Unknown'):
            release_manifest.load_third_party_inventory(self.root)

    def test_inconsistent_project_versions_or_hashes_are_refused(self):
        for version, sha512 in [('2.0.0', 'first-hash'), ('1.0.0', 'different-hash')]:
            with self.subTest(version=version, sha512=sha512):
                self.write_assets('Gui', version, sha512)
                with self.assertRaisesRegex(SystemExit, 'Conflicting resolved'):
                    release_manifest.load_third_party_inventory(self.root)

    def test_missing_restore_has_an_actionable_error(self):
        (self.root / 'Gui/obj/project.assets.json').unlink()
        with self.assertRaisesRegex(SystemExit, 'Restore Gui/Gui.csproj'):
            release_manifest.load_third_party_inventory(self.root)


if __name__ == '__main__':
    unittest.main()
