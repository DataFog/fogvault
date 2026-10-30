import {test, expect, chromium, firefox} from '@playwright/test';
import {mkdtemp, mkdir, cp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repository = resolve(packageRoot, '../..');
const required = JSON.parse(await readFile(join(repository, 'conformance/maintained-contract.json'), 'utf8')).browser_sdk.required_cases;

async function fixture(browser) {
  const temporary = await mkdtemp(join(tmpdir(), 'fogvault-extension-'));
  const extension = join(temporary, 'extension');
  await mkdir(extension);
  await cp(join(packageRoot, 'dist'), join(extension, 'sdk'), {recursive: true});
  for (const name of ['background.js', 'main.mjs', 'vault.html'])
    await cp(join(packageRoot, 'examples/extension', name), join(extension, name));
  const manifest = JSON.parse(await readFile(join(packageRoot, 'examples/extension', `manifest.${browser}.json`), 'utf8'));
  await writeFile(join(extension, 'manifest.json'), JSON.stringify(manifest));
  await writeFile(join(extension, 'test.html'), '<!doctype html><pre id="result"></pre><script type="module" src="test.mjs"></script>');
  const source = (await readFile(join(packageRoot, 'test/browser.mjs'), 'utf8')).replaceAll("../dist/", "./sdk/");
  await writeFile(join(extension, 'test.mjs'), source);
  return {temporary, extension, manifest};
}

function check(result, scheme) {
  expect(result.schema).toBe('fogvault-browser-sdk-acceptance/v1');
  expect(result.pass, result.error).toBe(true);
  expect(result.cases.map(item => item.id).sort()).toEqual([...required].sort());
  expect(result.cases.every(item => item.status === 'pass' && item.executed === true)).toBe(true);
  expect(scheme).toMatch(/^(chrome|moz)-extension:$/);
}

test('Chromium MV3 extension runs the SDK and reopens after its owner page closes', async () => {
  const {temporary, extension} = await fixture('chrome');
  let context;
  try {
    context = await chromium.launchPersistentContext(join(temporary, 'profile'), {
      channel: 'chromium',
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    });
    let [background] = context.serviceWorkers();
    if (!background) background = await context.waitForEvent('serviceworker');
    const backgroundUrl = new URL(background.url());
    const origin = `${backgroundUrl.protocol}//${backgroundUrl.host}`;
    const page = await context.newPage();
    await page.goto(origin + '/test.html');
    const result = await page.evaluate(() => window.fogvaultSdkDone);
    check(result, new URL(page.url()).protocol);
    const saved = await page.evaluate(async () => {
      const {FogVault, randomId} = await import('./sdk/client.mjs');
      const name = 'SYNTHETIC-extension-page-restart-' + crypto.randomUUID();
      const owner = new FogVault({limits: {payload: 64, metadata: 16, records: 4}, storageProfile: "arraybuffer", kdfProfiles: [{memory_kib: 65536, passes: 3}]});
      const id = randomId();
      await owner.create(name, 'SYNTHETIC extension restart');
      await owner.save(id, new Uint8Array(), new TextEncoder().encode('SYNTHETIC persistent extension bytes'), {expectedRevision: 0n});
      return {name, id: Array.from(id)};
    });
    await page.close(); // Actual privileged owner page and its Worker disappear.
    const reopened = await context.newPage();
    await reopened.goto(origin + '/vault.html');
    const payload = await reopened.evaluate(async ({name, id}) => {
      const {FogVault} = await import('./sdk/client.mjs');
      const owner = new FogVault({limits: {payload: 64, metadata: 16, records: 4}, storageProfile: "arraybuffer", kdfProfiles: [{memory_kib: 65536, passes: 3}]});
      await owner.open(name);
      await owner.unlock('SYNTHETIC extension restart');
      const record = await owner.read(Uint8Array.from(id));
      const result = new TextDecoder().decode(record.payload);
      await owner.close();
      return result;
    }, saved);
    expect(payload).toBe('SYNTHETIC persistent extension bytes');
  } finally {
    await context?.close();
    await rm(temporary, {recursive: true, force: true});
  }
});

test('Firefox WebExtension runs the SDK in its actual privileged extension origin', async () => {
  const {temporary, extension, manifest} = await fixture('firefox');
  const token = crypto.randomUUID();
  let receive, reject;
  const delivered = new Promise((resolve, fail) => { receive = resolve; reject = fail; });
  const server = createServer((request, response) => {
    if (request.method !== 'POST' || request.url !== '/' + token) { response.writeHead(404); response.end(); return; }
    let body = '';
    request.setEncoding('utf8');
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      try { receive(JSON.parse(body)); response.end('accepted'); }
      catch (error) { reject(error); response.writeHead(400); response.end(); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let child;
  try {
    manifest.host_permissions = ['http://127.0.0.1/*']; // Test-only result delivery.
    await writeFile(join(extension, 'manifest.json'), JSON.stringify(manifest));
    const source = await readFile(join(extension, 'test.mjs'), 'utf8');
    const callback = `http://127.0.0.1:${server.address().port}/${token}`;
    await writeFile(join(extension, 'test.mjs'), source + `\nwindow.fogvaultSdkDone.then(result => fetch(${JSON.stringify(callback)}, {method:'POST', body:JSON.stringify({result,scheme:location.protocol})}));\n`);
    const background = await readFile(join(extension, 'background.js'), 'utf8');
    await writeFile(join(extension, 'background.js'), background + '\n(globalThis.browser || globalThis.chrome).runtime.onInstalled.addListener(() => (globalThis.browser || globalThis.chrome).tabs.create({url:(globalThis.browser || globalThis.chrome).runtime.getURL("test.html")}));\n');
    const output = [];
    child = spawn(process.execPath, [join(packageRoot, 'node_modules/web-ext/bin/web-ext.js'),
      'run', '--source-dir', extension, '--firefox', firefox.executablePath(),
      '--no-reload', '--no-input', '--no-config-discovery', '--args=-headless'], {stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', bytes => output.push(bytes.toString()));
    child.stderr.on('data', bytes => output.push(bytes.toString()));
    child.on('error', reject);
    child.on('exit', code => { if (code) reject(Error('Firefox extension runner exited: ' + output.join(''))); });
    const {result, scheme} = await delivered;
    check(result, scheme);
  } finally {
    child?.kill('SIGINT');
    await new Promise(resolve => server.close(resolve));
    await rm(temporary, {recursive: true, force: true});
  }
});
