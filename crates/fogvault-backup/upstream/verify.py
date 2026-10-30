#!/usr/bin/env python3
"""Check all retained source archives, vendored bytes and declared patch scope."""
import hashlib,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sha=lambda value:hashlib.sha256(value).hexdigest()
provenance=json.loads((ROOT/'upstream/provenance.json').read_text())
expected=json.loads((ROOT/'upstream/vendor-files.json').read_text())
actual={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in (ROOT/'vendor').rglob('*') if p.is_file()}
assert actual=={row['path']:row['sha256'] for row in expected},'vendored files changed'
patches={row['path']:row for row in provenance['modified_files']}
for package in provenance['packages']:
 archive=ROOT/package['archive'];assert sha(archive.read_bytes())==package['sha256']
 name=f"{package['name']}-{package['version']}"
 with tarfile.open(archive,'r:gz') as tar:
  original={member.name.split('/',1)[1]:tar.extractfile(member).read() for member in tar.getmembers() if member.isfile()}
 vendor=ROOT/'vendor'/name
 files={p.relative_to(vendor).as_posix():p for p in vendor.rglob('*') if p.is_file()}
 assert set(original)-set(files)==set(package['omitted_archive_files'])
 for rel,data in original.items():
  if rel in package['omitted_archive_files']:continue
  path=f'vendor/{name}/{rel}';current=files[rel].read_bytes()
  if data!=current:
   row=patches[path];assert sha(data)==row['upstream_sha256'] and sha(current)==row['patched_sha256']
   assert not path.startswith('vendor/age-0.11.5/src/'),'age cryptographic source changed'
assert provenance['age_rust_sources_byte_identical'] and not provenance['advisory_suppressions']
print(json.dumps({'pass':True,'vendor_files':len(expected),'declared_noncrypto_patches':len(patches),'age_rust_sources_byte_identical':True}))
