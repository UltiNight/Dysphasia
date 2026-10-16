// Executes the cloned REA CLI. Keeps full stdout/stderr and a live event ledger.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, appendFile, readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [runId, label, ...args] = process.argv.slice(2);
if (!runId || !label || !args.length || !/^[a-zA-Z0-9_-]+$/.test(runId + label)) {
  throw new Error('Usage: node scripts/rea-run.mjs RUN LABEL <REA CLI arguments>');
}
const staticCommands = new Set(['inspect-managed-artifact', 'inspect-managed-members', 'inspect-managed-native-boundaries', 'compare-managed-members']);
if (!staticCommands.has(args[0])) throw new Error('This recorder supports managed static-analysis commands only.');
const out = resolve(root, 'logs', runId);
await mkdir(out, { recursive: true });
const base = resolve(out, label);
const stdout = createWriteStream(base + '.stdout.json', { flags: 'wx' });
const stderr = createWriteStream(base + '.stderr.log', { flags: 'wx' });
// Never copy the ambient environment into reports.
const record = { run_id: runId, label, started_at_utc: new Date().toISOString(),
  node_version: process.version, command: [process.execPath, resolve(root, 'third_party/rea/scripts/rea.mjs'), ...args],
  cwd: root, target_execution: false };
let journal = Promise.resolve();
function log(event) {
  const line = JSON.stringify({ at_utc: new Date().toISOString(), label, ...event }) + '\n';
  journal = journal.then(() => appendFile(resolve(out, 'events.jsonl'), line));
}
log({ event: 'start', command: record.command });
console.log(`[${record.started_at_utc}] ${label}: started`);
const start = performance.now();
const child = spawn(process.execPath, record.command.slice(1), { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
child.stdout.on('data', data => { stdout.write(data); log({ event: 'stdout', bytes: data.length }); });
child.stderr.on('data', data => { stderr.write(data); log({ event: 'stderr', bytes: data.length }); });
const tick = setInterval(() => console.log(`${label}: ${(performance.now() - start).toFixed(0)} ms elapsed`), 15000);
const timeout = setTimeout(() => { record.timed_out = true; child.kill(); }, 180000);
try {
  const exit = await new Promise((accept, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => accept({ code, signal }));
  });
  Object.assign(record, exit, { elapsed_ms: performance.now() - start, finished_at_utc: new Date().toISOString() });
} finally {
  clearInterval(tick); clearTimeout(timeout);
  await Promise.all([new Promise(r => stdout.end(r)), new Promise(r => stderr.end(r))]);
}
for (const suffix of ['.stdout.json', '.stderr.log']) {
  record[suffix.slice(1) + '_sha256'] = createHash('sha256').update(await readFile(base + suffix)).digest('hex');
}
log({ event: 'finish', exit_code: record.code, elapsed_ms: record.elapsed_ms });
await journal;
await writeFile(base + '.meta.json', JSON.stringify(record, null, 2));
console.log(JSON.stringify(record, null, 2));
process.exitCode = record.code === 0 ? 0 : 1;
