"""Inventory resolved package bytes, selected TFMs/native assets and declared licenses."""
import argparse
import base64
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--assets', required=True)
parser.add_argument('--package-root', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
assets_path = Path(args.assets)
assets_bytes = assets_path.read_bytes()
assets = json.loads(assets_bytes)
cache = Path(args.package_root)
records = []
for name, library in sorted(assets['libraries'].items()):
    if library['type'] != 'package':
        continue
    package_id, version = name.rsplit('/', 1)
    folder = cache / library['path']
    archive = folder / (package_id.lower() + '.' + version.lower() + '.nupkg')
    actual = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    expected = library['sha512'].removeprefix('sha512-')
    archive_hash_from_cache = (folder / (archive.name + '.sha512')).read_text(encoding='utf-8').strip()
    cache_metadata = json.loads((folder / '.nupkg.metadata').read_text(encoding='utf-8'))
    nuspec_path = next(folder.glob('*.nuspec'))
    nuspec_bytes = nuspec_path.read_bytes()
    metadata = ET.fromstring(nuspec_bytes).find('{*}metadata')
    license_element = metadata.find('{*}license')
    license_url = metadata.findtext('{*}licenseUrl')
    license_record = {'type': license_element.get('type'), 'value': license_element.text} if license_element is not None else {'type': 'legacy-url-or-unspecified', 'value': license_url}
    if license_element is not None and license_element.get('type') == 'file':
        license_file = folder / license_element.text
        license_record['file_sha256'] = hashlib.sha256(license_file.read_bytes()).hexdigest() if license_file.exists() else None
    selected = {}
    for target, packages in assets['targets'].items():
        if name not in packages:
            continue
        entry = packages[name]
        selected[target] = {'compile': list(entry.get('compile', {})), 'runtime': list(entry.get('runtime', {})),
                            'native': list(entry.get('native', {})),
                            'runtimeTargets': entry.get('runtimeTargets', {})}
    records.append({'id': package_id, 'version': version, 'lock_content_sha512_base64': expected,
                    'cache_recorded_content_sha512_base64': cache_metadata['contentHash'],
                    'cache_recorded_archive_sha512_base64': archive_hash_from_cache,
                    'actual_nupkg_archive_sha512_base64': actual,
                    'verified': actual == archive_hash_from_cache and cache_metadata['contentHash'] == expected,
                    'cache_source': cache_metadata.get('source'),
                    'nuspec_sha256': hashlib.sha256(nuspec_bytes).hexdigest(), 'declared_license': license_record,
                    'selected_assets': selected})

report = {'scope': 'Resolved-artifact inventory: actual archive bytes match cache archive hash; cache content hash matches lock/assets. Signed archive and unsigned NuGet content hashes are distinct. This does not independently recompute NuGet content hashes or establish publisher signature trust, legal compatibility or vulnerability assurance.',
          'hash_semantics_source': 'https://github.com/NuGet/Home/wiki/Nupkg-Metadata-File',
          'assets_sha256': hashlib.sha256(assets_bytes).hexdigest(), 'package_count': len(records),
          'all_package_hashes_verified': all(r['verified'] for r in records),
          'restore_logs': assets.get('logs', []), 'packages': records}
Path(args.output).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print('Resolved packages:', len(records), '; all archive hashes verified:', report['all_package_hashes_verified'])
raise SystemExit(0 if report['all_package_hashes_verified'] else 1)
