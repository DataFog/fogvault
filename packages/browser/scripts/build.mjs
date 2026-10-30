import {spawnSync} from 'node:child_process';
import {mkdir, copyFile, readdir, rm} from 'node:fs/promises';
import {dirname, resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {collectNotices} from './collect-notices.mjs';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repository = resolve(packageRoot, '../..');
const crate = join(repository, 'crates/fogvault-wasm');
const destination = join(packageRoot, 'dist');
function run(command, args) {
  const result = spawnSync(command, args, {cwd: repository, stdio: 'inherit'});
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}
const version = spawnSync('wasm-bindgen', ['--version'], {encoding: 'utf8'});
if (version.status !== 0 || version.stdout.trim() !== 'wasm-bindgen 0.2.127') throw Error('wasm-bindgen CLI 0.2.127 is required to match the locked binding crate');
run('cargo', ['build', '--locked', '--manifest-path', join(crate, 'Cargo.toml'), '--target', 'wasm32-unknown-unknown', '--release']);
const target = process.env.CARGO_TARGET_DIR ? resolve(repository, process.env.CARGO_TARGET_DIR) : join(crate, 'target');
await rm(destination, {recursive: true, force: true});
await mkdir(join(destination, 'wasm'), {recursive: true});
run('wasm-bindgen', [join(target, 'wasm32-unknown-unknown/release/fogvault_wasm.wasm'), '--target', 'web', '--out-dir', join(destination, 'wasm')]);
for (const name of await readdir(join(packageRoot, 'src'))) {
  if (name.endsWith('.mjs') || name.endsWith('.d.ts')) await copyFile(join(packageRoot, 'src', name), join(destination, name));
}
await copyFile(join(repository, 'LICENSE'), join(packageRoot, 'LICENSE'));
await collectNotices(repository, packageRoot, destination);
console.log('Built', destination);
