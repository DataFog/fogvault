import {cp, copyFile, mkdir, rm} from 'node:fs/promises';
import {dirname, resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const browser = process.argv[2] || 'chrome';
if (!['chrome', 'firefox'].includes(browser)) throw Error('choose chrome or firefox');
await rm(join(root, 'examples/website/sdk'), {recursive: true, force: true});
await cp(join(root, 'dist'), join(root, 'examples/website/sdk'), {recursive: true});
const output = join(root, 'example-build', browser);
await rm(output, {recursive: true, force: true});
await mkdir(output, {recursive: true});
for (const name of ['background.js', 'main.mjs', 'vault.html']) await copyFile(join(root, 'examples/extension', name), join(output, name));
await copyFile(join(root, 'examples/extension', `manifest.${browser}.json`), join(output, 'manifest.json'));
await cp(join(root, 'dist'), join(output, 'sdk'), {recursive: true, force: true});
console.log('Website:', join(root, 'examples/website'));
console.log('Extension:', output);
