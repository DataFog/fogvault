#!/usr/bin/env python3
"""Execute new maintained backend against the pinned official Go age CLI.

All record/key material is synthetic. Private keys remain in memory/pipe and are
never put in arguments, environment variables, disk files or returned reports.
This local profile explicitly requires its macOS arm64 reference executable.
"""
import hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
PROJECT=ROOT/'crates/fogvault-backup'
GO=ROOT/'research/review-dependencies/age-v1.3.2/bin/age'
EXPECTED='4012dfc2725883beafb710894af4f599b7a94f8c8e0f51f02cc96ab8df33915e'
def run(args, data=None, pass_fds=()):
    p=subprocess.run([str(a) for a in args],cwd=ROOT,input=data,capture_output=True,pass_fds=pass_fds,check=True)
    return p.stdout
if hashlib.sha256(GO.read_bytes()).hexdigest()!=EXPECTED:raise ValueError('pinned Go reference differs')
run(['cargo','build','--locked','--manifest-path',PROJECT/'Cargo.toml','--example','interop'])
metadata=json.loads(run(['cargo','metadata','--locked','--no-deps','--format-version','1','--manifest-path',PROJECT/'Cargo.toml']))
program=Path(metadata['target_directory'])/'debug/examples/interop'
secret,recipient=run([program,'keygen']).splitlines()
cipher=run([program,'export',recipient.decode('ascii')])
read,write=os.pipe()
try:
    os.write(write,secret+b'\n');os.close(write)
    plain=run([GO,'--decrypt','-i',f'/dev/fd/{read}'],cipher,(read,))
finally:os.close(read)
expected=(ROOT/'conformance/export-vectors-records.bin').read_bytes()
if plain!=expected:raise ValueError('Go did not decrypt exact maintained Rust FVEXP001 payload')
go_cipher=run([GO,'--encrypt','-r',recipient.decode('ascii')],expected)
result=json.loads(run([program,'import',hashlib.sha256(go_cipher).hexdigest()],secret+b'\n'+go_cipher))
if result!={'pass':True,'records':2,'origin_verified':True}:raise ValueError('new Rust backend did not verify Go output')
report={'pass':True,'schema':'fogvault-maintained-age-interop/v1','go_version':run([GO,'--version']).decode().strip(),'go_sha256':EXPECTED,'rust_to_go':True,'go_to_rust':True,'payload_sha256':hashlib.sha256(expected).hexdigest(),'ciphertext_rust_sha256':hashlib.sha256(cipher).hexdigest(),'ciphertext_go_sha256':hashlib.sha256(go_cipher).hexdigest(),'plaintext_or_private_key_files':False,'scope':'single pinned Apple-arm64 interoperability run; not whole-platform qualification'}
(PROJECT/'upstream/interop-20261030.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
