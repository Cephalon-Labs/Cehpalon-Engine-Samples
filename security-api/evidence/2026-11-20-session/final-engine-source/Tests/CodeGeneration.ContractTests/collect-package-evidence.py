"""Record actual raw archives, distinct NuGet content hashes and package license metadata.

Read-only against the NuGet cache. It does not verify publisher signatures or
approve redistribution. No package files are executed by this collector.
"""
import argparse
import base64
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
generator = root/'src/Cehpalon.Engine.CodeGeneration'
tests = root/'Tests/CodeGeneration.ContractTests'
lock_paths = [generator/'packages.lock.json', tests/'packages.lock.json', tests/'CompilerFixture/packages.lock.json']
package_folders = list(json.loads((generator/'obj/project.assets.json').read_text())['packageFolders'])
if len(package_folders) != 1:
    raise SystemExit('Expected exactly one explicit NuGet package cache')
cache = Path(package_folders[0])
packages = {}
for lock_path in lock_paths:
    for framework, graph in json.loads(lock_path.read_text())['dependencies'].items():
        for name, item in graph.items():
            if item['type'].lower() == 'project':
                continue
            key = (name.lower(), item['resolved'])
            record = packages.setdefault(key, {'name':name,'version':item['resolved'],'lock_content_hashes':set(),'graphs':[]})
            record['lock_content_hashes'].add(item['contentHash'])
            record['graphs'].append(str(lock_path.relative_to(root))+':'+framework)

result = {'observed_at_utc':datetime.now(timezone.utc).isoformat(),
          'scope':'Actual cached archive identity and recorded package license metadata; not publisher-signature, code security or redistribution approval',
          'hash_boundary':'Raw signed nupkg hashes match cache .nupkg.sha512. NuGet .nupkg.metadata contentHash is compared separately with lock contentHash. These may differ for signed packages.',
          'packages':[]}
for (name, version), item in sorted(packages.items()):
    folder = cache/name/version
    archive = folder/(name+'.'+version+'.nupkg')
    actual = archive.read_bytes()
    cache_raw_hash = (folder/(name+'.'+version+'.nupkg.sha512')).read_text().strip()
    cache_metadata = json.loads((folder/'.nupkg.metadata').read_text())
    content_hash = cache_metadata['contentHash']
    item['lock_content_hashes'] = sorted(item['lock_content_hashes'])
    item['cache_content_hash'] = content_hash
    item['cache_content_hash_matches_all_locks'] = item['lock_content_hashes'] == [content_hash]
    item['actual_raw_nupkg_bytes'] = len(actual)
    item['actual_raw_nupkg_sha256'] = hashlib.sha256(actual).hexdigest()
    item['actual_raw_nupkg_sha512_base64'] = base64.b64encode(hashlib.sha512(actual).digest()).decode()
    item['cache_raw_archive_sha512_base64'] = cache_raw_hash
    item['actual_raw_archive_matches_cache_hash'] = item['actual_raw_nupkg_sha512_base64'] == cache_raw_hash
    item['cache_source'] = cache_metadata.get('source')
    with zipfile.ZipFile(archive) as package:
        nuspecs = [entry for entry in package.namelist() if entry.lower().endswith('.nuspec')]
        if len(nuspecs) != 1:
            raise ValueError('Expected single nuspec: '+str(archive))
        data = package.read(nuspecs[0])
        metadata = ET.fromstring(data).find('{*}metadata')
        license = metadata.find('{*}license')
        url = metadata.find('{*}licenseUrl')
        repository = metadata.find('{*}repository')
        item['nuspec_sha256'] = hashlib.sha256(data).hexdigest()
        item['declared_license'] = None if license is None else {'type':license.attrib.get('type'),'value':license.text}
        item['declared_license_url'] = None if url is None else url.text
        item['declared_repository'] = None if repository is None else repository.attrib
        item['license_notice_files'] = []
        for info in package.infolist():
            if not info.is_dir() and any(part in Path(info.filename).name.lower() for part in ('license','notice')):
                if info.file_size > 2*1024*1024:
                    raise ValueError('Unexpectedly large license file')
                data = package.read(info)
                item['license_notice_files'].append({'path':info.filename,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    if not item['cache_content_hash_matches_all_locks'] or not item['actual_raw_archive_matches_cache_hash']:
        raise ValueError('Cache/lock content hash mismatch: '+name)
    result['packages'].append(item)
result['package_count'] = len(result['packages'])
destination = Path(args.output)
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'package_count':result['package_count'],'cache_lock_content_hashes_match':True}))
