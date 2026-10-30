#!/usr/bin/env python3
"""Execute the disposable P2 Worker/WASM/IndexedDB fixture in real browser engines."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources

PROJECT=ROOT/'experiments/browser-prototype'
MANIFEST=PROJECT/'Cargo.toml'
CORE=ROOT/'crates/fogvault'

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def source_identity():
    paths=[Path(__file__),ROOT/'scripts/playwright-cli.sh',MANIFEST,PROJECT/'Cargo.lock',ROOT/'experiments/vault-prototype/Cargo.toml',ROOT/'experiments/vault-prototype/Cargo.lock',ROOT/'conformance/password-vectors.json']
    paths.extend(sorted((PROJECT/'src').rglob('*.rs')))
    paths.extend(sorted((PROJECT/'web').rglob('*')))
    paths.extend(sorted((ROOT/'experiments/vault-prototype/src').rglob('*.rs')))
    paths.extend([CORE/'Cargo.toml',CORE/'Cargo.lock',*sorted((CORE/'src').rglob('*.rs')),*sorted((CORE/'tests').rglob('*.rs')),*sorted((CORE/'examples').rglob('*.rs'))])
    paths.extend(maintained_sources(ROOT))
    return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(set(paths)) if p.is_file()}

class Handler(SimpleHTTPRequestHandler):
    def log_message(self,*args):pass
    def end_headers(self):self.send_header('Cache-Control','no-store');super().end_headers()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--engines',nargs='+',choices=['chromium','webkit'],default=['chromium','webkit'])
    parser.add_argument('--playwright-cli',type=Path,help='CLI executable/wrapper; defaults to installed CLI or the pinned repository wrapper')
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists; choose a fresh evidence destination')
    if len(args.engines)!=len(set(args.engines)):parser.error('engine names must be unique')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    log_dir=args.output.parent/(args.output.stem+'.logs');log_dir.mkdir(exist_ok=False)
    identity=source_identity();started=time.perf_counter();commands=[];engines=[];artifacts=[];failure=None
    cli=args.playwright_cli or os.environ.get('FOGVAULT_PLAYWRIGHT_CLI') or shutil.which('playwright-cli') or ROOT/'scripts/playwright-cli.sh'
    cli=str(cli)
    def run(name,command):
        log=log_dir/(name+'.log');p=subprocess.run([str(a) for a in command],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,check=False,env={**os.environ,'CARGO_TERM_COLOR':'never'})
        log.write_text(p.stdout);commands.append({'id':name,'command':[str(a) for a in command],'exit_code':p.returncode,'log':str(log)})
        if p.returncode:raise RuntimeError(f'{name} failed; inspect {log}')
        return p.stdout
    server=None;active=[]
    try:
        version=run('wasm-bindgen-version',['wasm-bindgen','--version']).strip()
        if version!='wasm-bindgen 0.2.127':raise RuntimeError('wasm-bindgen CLI must match pinned crate 0.2.127')
        cli_version=run('playwright-cli-version',[cli,'--version']).strip()
        password_adapter_node=json.loads(run('password-adapter-node',['node',PROJECT/'web/password-contract-node.mjs']))
        if password_adapter_node.get('schema')!='fogvault-browser-password-adapter-node/v1' or password_adapter_node.get('pass') is not True:
            raise RuntimeError('Node-only password adapter preflight failed')
        run('format',['cargo','fmt','--manifest-path',MANIFEST,'--check'])
        run('clippy',['cargo','clippy','--locked','--manifest-path',MANIFEST,'--target','wasm32-unknown-unknown','--','-D','warnings'])
        run('build',['cargo','build','--locked','--release','--manifest-path',MANIFEST,'--target','wasm32-unknown-unknown'])
        metadata=json.loads(run('metadata',['cargo','metadata','--locked','--no-deps','--format-version','1','--manifest-path',MANIFEST]))
        wasm=Path(metadata['target_directory'])/'wasm32-unknown-unknown/release/fogvault_browser_feasibility.wasm'
        run('generate-bindings',['wasm-bindgen',wasm,'--target','web','--out-dir',PROJECT/'pkg'])
        for p in sorted((PROJECT/'pkg').glob('*')):
            if p.is_file():artifacts.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size})
        if source_identity()!=identity:raise RuntimeError('browser input sources changed during build')
        server=ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(ROOT)))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base=f'http://127.0.0.1:{server.server_port}/experiments/browser-prototype/web/index.html'
        for name in args.engines:
            session='fogvault-feasibility-'+name+'-'+uuid.uuid4().hex
            active.append(session)
            run(name+'-open',[cli,'--session',session,'open',base+('?storage=arraybuffer' if name=='webkit' else '?storage=blob'),'--browser','chrome' if name=='chromium' else 'webkit'])
            text=run(name+'-result',[cli,'--session',session,'--raw','run-code','async page => await page.evaluate(() => window.fogvaultDone)'])
            result=json.loads(text)
            engines.append({'name':name,'result':result})
            if result.get('schema')!='fogvault-browser-feasibility/v1' or result.get('pass') is not True:raise RuntimeError(f'{name} fixture failed; inspect retained result log')
            run(name+'-close',[cli,'--session',session,'close']);active.remove(session)
        if source_identity()!=identity:raise RuntimeError('browser input sources changed during execution')
    except (OSError,ValueError,RuntimeError,KeyError) as error:failure=str(error)
    finally:
        for session in active:
            try:run('cleanup-'+session,[cli,'--session',session,'close'])
            except (OSError,RuntimeError):pass
        if server:server.shutdown();server.server_close()
    report={'schema':'fogvault-browser-feasibility/v1','pass':failure is None and len(engines)==len(args.engines),'recorded_at_utc':datetime.now(timezone.utc).isoformat(),'duration_seconds':time.perf_counter()-started,'source_identity':identity,'artifacts':artifacts,'engines':engines,'commands':commands,'password_adapter_node':locals().get('password_adapter_node'),'environment':{'platform':platform.platform(),'python':sys.version,'wasm_bindgen':locals().get('version'),'playwright_cli':locals().get('cli_version')},'unqualified_scopes':['physical Android/iOS devices','Safari/iOS product qualification','browser extension/service-worker lifecycle','large/adversarial browser workloads beyond the recorded startup populations','power-loss durability and eviction/persistence guarantees','universal JS/engine memory erasure or forced-termination finalizers','SharedArrayBuffer Worker/WASM runtime behavior on browser profiles where the constructor is unavailable; Node helper checks do not qualify those browser paths','production cryptographic assurance and certification']}
    if failure:report['error']=failure
    with args.output.open('x') as dest:json.dump(report,dest,indent=2);dest.write('\n')
    print(f"{'PASS' if report['pass'] else 'FAIL'} browser feasibility: {args.output}")
    if failure:print(failure,file=sys.stderr)
    return 0 if report['pass'] else 1

if __name__=='__main__':raise SystemExit(main())
