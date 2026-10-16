import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const json = async p => JSON.parse((await readFile(resolve(root, p), 'utf8')).replace(/^\uFEFF/, ''));
const observations = [];
for (const pass of ['pass01', 'pass02']) {
  for (const name of ['01-artifact', '02-members']) {
    const prefix = `logs/${pass}/${name}`;
    const evidence = await json(prefix + '.stdout.json');
    const meta = await json(prefix + '.meta.json');
    if (meta.code !== 0 || !evidence.evidence_id) throw new Error(`Failed evidence: ${prefix}`);
    const r = evidence.normalized_result;
    observations.push({ pass, operation: evidence.operation, evidence_id: evidence.evidence_id,
      elapsed_ms: meta.elapsed_ms, target_sha256: evidence.subject.digest.sha256,
      coverage: r.coverage, limitations: evidence.limitations, output_sha256: meta['stdout.json_sha256'],
      types: r.types?.map(t => ({ token: t.token, name: t.full_name })),
      methods: r.methods?.map(m => ({ token: m.token, name: m.name,
        body: m.body ?? m.cil ?? null })),
      user_strings: r.user_strings,
      call_edge_count: r.call_edges?.length });
  }
}
const summary = { observations, same_artifact: new Set(observations.map(o=>o.target_sha256)).size === 1,
  repeated_output_identical: ['inspect_managed_artifact','inspect_managed_members'].every(op =>
    new Set(observations.filter(o=>o.operation === op).map(o=>o.output_sha256)).size === 1),
  timing_caveat: 'Separate CLI processes on the same host; OS caches were not flushed. First invocation is not a controlled cold benchmark.',
  jsonl_caveat: 'Events record command/chunk/exit timing, not internal parser passes, CPU/memory, or private model reasoning.' };
await mkdir(resolve(root,'reports'), { recursive: true });
await writeFile(resolve(root,'reports/rea-summary.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify({ same_artifact: summary.same_artifact,
  repeated_output_identical: summary.repeated_output_identical,
  observations: observations.map(({pass,operation,evidence_id,elapsed_ms,coverage})=>({pass,operation,evidence_id,elapsed_ms,coverage})) }, null, 2));
