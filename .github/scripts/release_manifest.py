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
    catalog = json.loads(path.read_text(encoding='utf-8'))
    recorded = {item['name']: item for item in catalog['components']}
    if len(recorded) != len(catalog['components']):
        raise SystemExit('Third-party catalog contains duplicate component names')
    actual = {}
    for project in catalog['projects']:
        assets = root / Path(project).parent / 'obj/project.assets.json'
        if not assets.is_file():
            raise SystemExit(f'Restore {project} before generating the component inventory')
        libraries = json.loads(assets.read_text(encoding='utf-8'))['libraries']
        for identity, library in libraries.items():
            if library['type'] != 'package':
                continue
            name, version = identity.rsplit('/', 1)
            resolved = {'version': version, 'sha512': library['sha512']}
            if actual.setdefault(name, resolved) != resolved:
                raise SystemExit(f'Conflicting resolved versions or hashes for {name}')
    if actual.keys() != recorded.keys():
        missing = sorted(actual.keys() - recorded.keys())
        stale = sorted(recorded.keys() - actual.keys())
        raise SystemExit(f'Third-party catalog needs license review; missing={missing}, stale={stale}')
    inventory = {
        'schemaVersion': 2,
        'projects': catalog['projects'],
        'components': [dict(recorded[name], **actual[name])
                       for name in sorted(actual, key=str.casefold)],
    }
    return path, inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path, nargs='?')
    parser.add_argument('--check-only', action='store_true', help='validate the checked-in third-party inventory')
    parser.add_argument('--inventory-output', type=Path, help='write resolved component versions and hashes for packaging')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    inventory_path, inventory = load_third_party_inventory(root)
    if args.check_only:
        print(f"Validated {len(inventory['components'])} third-party components")
        return
    if args.inventory_output is not None:
        args.inventory_output.parent.mkdir(parents=True, exist_ok=True)
        args.inventory_output.write_text(json.dumps(inventory, indent=2) + '\n', encoding='utf-8')
        return
    if args.assets is None:
        parser.error('assets is required unless --check-only or --inventory-output is used')
    installers = sorted(path for path in args.assets.iterdir()
                        if path.is_file() and path.suffix in {'.deb', '.rpm', '.pkg', '.msi', '.exe'})
    if not installers:
        parser.error('No installer artifacts found')
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
        shutil.copy2(root / name, args.assets / name)
    (args.assets / 'THIRD-PARTY-COMPONENTS.json').write_text(
        json.dumps(inventory, indent=2) + '\n', encoding='utf-8')
    assets = installers + [args.assets / 'LICENSE', args.assets / 'THIRD-PARTY-NOTICES.md',
                           args.assets / 'THIRD-PARTY-COMPONENTS.json']
    checksums = {path.name: digest(path) for path in assets}
    (args.assets / 'SHA256SUMS').write_text(
        ''.join(f'{value}  {name}\n' for name, value in checksums.items()), encoding='utf-8')
    locks = [root / '.github/package-lock.json']
    manifest = {
        'schemaVersion': 3,
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
        'manifestDotnetSdk': subprocess.check_output(
            ['dotnet', '--version'], cwd=root, text=True).strip(),
        'artifacts': [{'name': path.name, 'size': path.stat().st_size,
                       'sha256': checksums[path.name]} for path in assets],
        'dependencyLocks': {str(path.relative_to(root)): {
            'sha256': digest(path), 'contents': json.loads(path.read_text())} for path in locks},
        'centralPackageVersions': {
            'path': 'Directory.Packages.props',
            'sha256': digest(root / 'Directory.Packages.props'),
        },
        'thirdPartyInventory': {
            'catalogSha256': digest(inventory_path),
            'contents': inventory,
        },
    }
    (args.assets / 'release-manifest.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
