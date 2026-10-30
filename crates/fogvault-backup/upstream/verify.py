#!/usr/bin/env python3
"""Check all retained source archives, vendored bytes and declared patch scope."""
import hashlib,json,tarfile,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sha=lambda value:hashlib.sha256(value).hexdigest()
provenance=json.loads((ROOT/'upstream/provenance.json').read_text())
expected=json.loads((ROOT/'upstream/vendor-files.json').read_text())
actual={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in (ROOT/'vendor').rglob('*') if p.is_file()}
assert actual=={row['path']:row['sha256'] for row in expected},'vendored files changed'
patches={row['path']:row for row in provenance['modified_files']}
added={row['path']:row['sha256'] for row in provenance['added_files']}
assert len(added)==5 and all(Path(path).name=='FOGVAULT-FORK.md' for path in added)
for path,digest in added.items():assert sha((ROOT/path).read_bytes())==digest
for package in provenance['packages']:
 archive=ROOT/package['archive'];assert sha(archive.read_bytes())==package['sha256']
 name=f"{package['name']}-{package['version']}"
 with tarfile.open(archive,'r:gz') as tar:
  original={member.name.split('/',1)[1]:tar.extractfile(member).read() for member in tar.getmembers() if member.isfile()}
 vendor=ROOT/'vendor'/name
 manifest=tomllib.loads((vendor/'Cargo.toml').read_text())
 assert manifest['package']['name']==package['registry_name']=='fogvault-'+package['name']
 assert manifest['package']['version']==package['version']
 assert manifest['package']['metadata']['fogvault-upstream']['name']==package['name']
 assert manifest['package']['metadata']['fogvault-upstream']['version']==package['version']
 assert not any(field in manifest for field in ('dev-dependencies','bench','test','example','target'))
 assert manifest['package']['readme']=='FOGVAULT-FORK.md'
 files={p.relative_to(vendor).as_posix():p for p in vendor.rglob('*') if p.is_file()}
 assert set(original)-set(files)==set(package['omitted_archive_files'])
 expected_added={Path(path).relative_to('vendor/'+name).as_posix() for path in added if path.startswith('vendor/'+name+'/')}
 expected_added.update(Path(path).relative_to('vendor/'+name).as_posix() for path in provenance['license_supplement']['files'] if path.startswith('vendor/'+name+'/'))
 assert set(files)-set(original)==expected_added,'undeclared added upstream material'
 for rel,data in original.items():
  if rel in package['omitted_archive_files']:continue
  path=f'vendor/{name}/{rel}';current=files[rel].read_bytes()
  if data!=current:
   row=patches[path];assert sha(data)==row['upstream_sha256'] and sha(current)==row['patched_sha256']
   assert not path.startswith('vendor/age-0.11.5/src/'),'age cryptographic source changed'
assert provenance['age_rust_sources_byte_identical'] and not provenance['advisory_suppressions']
assert tomllib.loads((ROOT/'vendor/age-0.11.5/i18n.toml').read_text())['fluent']['domain']=='age'
print(json.dumps({'pass':True,'vendor_files':len(expected),'declared_noncrypto_patches':len(patches),'age_rust_sources_byte_identical':True}))
