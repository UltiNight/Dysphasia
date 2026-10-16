"""Eight explicitly logged probes; not the independent hidden evaluator."""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'reconstruction/pass01'
if (OUT / 'probe_results.json').exists():
    raise SystemExit('Probe results already exist; refusing to exceed the eight-probe budget.')
CASES = [
    ('help', ['--help']),
    ('arity', []),
    ('neutral_negative_truncation', ['1', '127', '129', '0', '33', 'neutral']),
    ('mono_weighting', ['13', '187', '244', '-17', '143', 'mono']),
    ('warm_clipping', ['250', '255', '0', '0', '100', 'warm']),
    ('numeric_error_precedes_preset', ['256', '0', '0', '0', '100', 'bogus']),
    ('case_sensitive_preset', ['1', '2', '3', '0', '100', 'Warm']),
    ('integer_sign_and_whitespace', [' \t+0013\r\n', ' -0 ', '+00255', ' +0 ', '0100', 'neutral']),
]

def log(action, **extra):
    with (OUT / 'actions.jsonl').open('a', encoding='utf-8') as f:
        f.write(json.dumps(dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), action=action, **extra), ensure_ascii=False)+'\n')

def capture(command):
    p = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=10)
    return dict(exit_code=p.returncode, stdout=p.stdout.decode('ascii'), stderr=p.stderr.decode('ascii'), stdout_hex=p.stdout.hex(), stderr_hex=p.stderr.hex())

results=[]
for index, (name, args) in enumerate(CASES, 1):
    log('target_probe_planned', probe_id=f'P{index:02}', name=name, argv=args, target='artifacts/baseline/PixelTone.exe')
    target = capture([str(ROOT/'artifacts/baseline/PixelTone.exe'), *args])
    clone = capture([sys.executable, str(OUT/'pixel_tone.py'), *args])
    item = dict(probe_id=f'P{index:02}', name=name, argv=args, target=target, clone=clone, match=target==clone)
    results.append(item)
    log('target_probe_result', **item)
    print(json.dumps(item, ensure_ascii=False))
(OUT/'probe_results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
log('probe_budget_exhausted', count=len(results), matched=sum(x['match'] for x in results), finding='No further target executions authorized in this reconstruction pass.')
