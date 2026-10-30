import {spawn} from 'node:child_process';
import {mkdir, readFile, writeFile, readdir, copyFile, cp} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {dirname, join, relative} from 'node:path';

const digest = value => createHash('sha256').update(value).digest('hex');
const notice = name => /^(LICENSE|COPYING|NOTICE|UNLICENSE)(?:[._-].*)?$/i.test(name);

/** Keep actual locked source-graph notices with the distributed WASM artifact. */
export async function collectNotices(repository, packageRoot, destination) {
  const outputText = await new Promise((resolve, reject) => {
    const child = spawn('cargo', ['metadata', '--locked', '--format-version', '1', '--filter-platform', 'wasm32-unknown-unknown',
      '--manifest-path', join(repository, 'crates/fogvault-wasm/Cargo.toml')], {cwd: repository, stdio: ['ignore', 'pipe', 'pipe']});
    const chunks = []; let failure = '';
    child.stdout.on('data', data => chunks.push(data)); child.stderr.on('data', data => { failure += data; });
    child.on('error', reject); child.on('close', code => code === 0 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(Error(failure)));
  });
  const metadata = JSON.parse(outputText), output = join(destination, 'third-party');
  await mkdir(output, {recursive: true});
  const supplements = JSON.parse(await readFile(join(packageRoot, 'notices/provenance.json'), 'utf8'));
  const supplementary = new Map(supplements.packages.map(row => [`${row.package}-${row.version}`, row]));
  const firstParty = new Set(['fogvault', 'fogvault-backup', 'fogvault-wasm']);
  const rows = [], seen = new Set();
  for (const item of metadata.packages.sort((a, b) => `${a.name}-${a.version}`.localeCompare(`${b.name}-${b.version}`))) {
    const id = `${item.name}-${item.version}`;
    if (seen.has(id)) throw Error('notice source identity collision: ' + id);
    seen.add(id);
    const directory = dirname(item.manifest_path), folder = join(output, id);
    await mkdir(folder, {recursive: true});
    const files = (await readdir(directory, {withFileTypes: true})).filter(entry => entry.isFile() && notice(entry.name)).map(entry => entry.name);
    if (files.length) {
      for (const file of files) await copyFile(join(directory, file), join(folder, file));
    } else if (firstParty.has(item.name)) {
      await copyFile(join(repository, 'LICENSE'), join(folder, 'LICENSE'));
    } else if (supplementary.has(id)) {
      const supplied = supplementary.get(id);
      for (const file of supplied.files) {
        const source = join(packageRoot, file.path), bytes = await readFile(source);
        if (digest(bytes) !== file.sha256) throw Error('supplementary notice changed: ' + file.path);
        await copyFile(source, join(folder, file.path.split('/').at(-1)));
      }
      await writeFile(join(folder, 'PROVENANCE.json'), JSON.stringify(supplied, null, 2) + '\n');
    } else throw Error('missing dependency notice: ' + id);
    // Some packages use a REUSE license directory alongside top-level notices.
    for (const entry of await readdir(directory, {withFileTypes: true})) if (entry.isDirectory() && entry.name === 'LICENSES') await cp(join(directory, entry.name), join(folder, entry.name), {recursive: true});
    const hashes = [];
    async function inventory(path) {
      for (const entry of await readdir(path, {withFileTypes: true})) {
        const file = join(path, entry.name);
        if (entry.isDirectory()) await inventory(file);
        else if (entry.isFile()) hashes.push({path: relative(output, file).replaceAll('\\', '/'), sha256: digest(await readFile(file))});
        else throw Error('nonregular notice refused');
      }
    }
    await inventory(folder);
    rows.push({name: item.name, version: item.version, source: item.source, license: item.license, files: hashes});
  }
  const rustNotices = join(repository, 'third-party/cargo-audit/rust-standard-library/COPYRIGHT-library.html');
  await copyFile(rustNotices, join(output, 'RUST-STANDARD-LIBRARY-COPYRIGHT.html'));
  await writeFile(join(output, 'inventory.json'), JSON.stringify({schema: 'fogvault-browser-wasm-notices/v1',
    scope: 'Locked, host-filtered Cargo source graph; includes build-time dependencies and is not a recovered binary SBOM',
    target: 'wasm32-unknown-unknown', packages: rows,
    rust_standard_library_notice_sha256: digest(await readFile(rustNotices))}, null, 2) + '\n');
  await writeFile(join(output, 'README.md'), '# WASM third-party notices\n\nThese package-specific terms apply to their own material. FogVault uses MIT.\n\nThe inventory describes the locked source graph filtered for wasm32-unknown-unknown,\nincluding host build dependencies; it is not a recovered binary SBOM. Pinned upstream\nlicense supplements are recorded separately where published crates omitted them.\nThe Rust standard-library notice is retained as an attribution supplement.\n');
  console.log('Collected WASM source-graph notices:', rows.length);
}
