"""Write release checksums, notices, and a source/dependency manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_third_party_inventory(root):
    path = root / 'packaging/third-party-components.json'
    inventory = json.loads(path.read_text(encoding='utf-8'))
    components = inventory['components']
    actual = {}
    for lock_name in inventory['lockFiles']:
        dependencies = json.loads((root / lock_name).read_text(encoding='utf-8'))['dependencies']['net10.0']
        for name, dependency in dependencies.items():
            if dependency.get('type') == 'Project':
                continue
            version = dependency.get('resolved')
            if version is not None and actual.setdefault(name, version) != version:
                raise SystemExit(f'Conflicting locked versions for {name}')
    recorded = {item['name']: item['version'] for item in components}
    if len(recorded) != len(components):
        raise SystemExit('Third-party inventory contains duplicate component names')
    if actual != recorded:
        missing = sorted(set(actual.items()) - set(recorded.items()))
        stale = sorted(set(recorded.items()) - set(actual.items()))
        raise SystemExit(f'Third-party inventory does not match production locks; missing={missing}, stale={stale}')
    return path, inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path, nargs='?')
    parser.add_argument('--check-only', action='store_true', help='validate the checked-in third-party inventory')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    inventory_path, inventory = load_third_party_inventory(root)
    if args.check_only:
        print(f"Validated {len(inventory['components'])} third-party components")
        return
    if args.assets is None:
        parser.error('assets is required unless --check-only is used')
    installers = sorted(path for path in args.assets.iterdir()
                        if path.is_file() and path.suffix in {'.deb', '.rpm', '.pkg', '.msi', '.exe'})
    if not installers:
        parser.error('No installer artifacts found')
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
        shutil.copy2(root / name, args.assets / name)
    shutil.copy2(inventory_path, args.assets / 'THIRD-PARTY-COMPONENTS.json')
    assets = installers + [args.assets / 'LICENSE', args.assets / 'THIRD-PARTY-NOTICES.md',
                           args.assets / 'THIRD-PARTY-COMPONENTS.json']
    checksums = {path.name: digest(path) for path in assets}
    (args.assets / 'SHA256SUMS').write_text(
        ''.join(f'{value}  {name}\n' for name, value in checksums.items()), encoding='utf-8')
    locks = sorted(root.glob('*/packages.lock.json')) + [root / '.github/package-lock.json']
    manifest = {
        'schemaVersion': 2,
        'platformCodeSigned': False,
        'provenance': {
            'type': 'github-artifact-attestation',
            'workflowRun': os.environ.get('GITHUB_RUN_ID'),
            'verification': 'gh attestation verify <artifact> --repo <owner/repository>',
        },
        'sourceCommit': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'sourceRepository': os.environ.get('GITHUB_REPOSITORY', 'ColDog-Studios/ColDog-Locker'),
        'workflowRun': os.environ.get('GITHUB_RUN_ID'),
        'sourceDateEpoch': int(os.environ['SOURCE_DATE_EPOCH']) if os.environ.get('SOURCE_DATE_EPOCH') else None,
        'dotnetSdk': json.loads((root / 'global.json').read_text())['sdk']['version'],
        'artifacts': [{'name': path.name, 'size': path.stat().st_size,
                       'sha256': checksums[path.name]} for path in assets],
        'dependencyLocks': {str(path.relative_to(root)): {
            'sha256': digest(path), 'contents': json.loads(path.read_text())} for path in locks},
        'thirdPartyInventory': {
            'sha256': digest(inventory_path),
            'contents': inventory,
        },
    }
    (args.assets / 'release-manifest.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
