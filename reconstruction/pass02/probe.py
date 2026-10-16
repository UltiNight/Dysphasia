"""Eight predeclared target input probes, after static-first implementation."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'reconstruction/pass02'
TARGET = ROOT / 'artifacts/baseline/PixelTone.exe'
RECON = OUT / 'pixel_tone.py'
CASES = [
    ['--help'],
    [],
    ['  +00127\t', '1', '254', '-3', '33', 'neutral'],
    ['255', '0', '128', '-100', '200', 'mono'],
    ['254', '254', '3', '0', '100', 'warm'],
    ['256', '0', '0', '0', '100', 'neutral'],
    ['0', '0', '0', '0', '100', 'Neutral'],
    ['\u00a01', '0', '0', '0', '100', 'neutral'],
]

def log(event):
    event['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (OUT / 'actions.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + '\n')

results = []
for index, args in enumerate(CASES, 1):
    log({'event': 'probe_start', 'probe': index, 'argv': args,
         'target_sha256': hashlib.sha256(TARGET.read_bytes()).hexdigest()})
    target = subprocess.run([str(TARGET), *args], capture_output=True, timeout=10)
    reconstructed = subprocess.run([sys.executable, str(RECON), *args], capture_output=True, timeout=10)
    result = {'probe': index, 'argv': args,
              'target': {'exit': target.returncode, 'stdout_hex': target.stdout.hex(), 'stderr_hex': target.stderr.hex()},
              'reconstruction': {'exit': reconstructed.returncode, 'stdout_hex': reconstructed.stdout.hex(), 'stderr_hex': reconstructed.stderr.hex()},
              'match': (target.returncode, target.stdout, target.stderr) == (reconstructed.returncode, reconstructed.stdout, reconstructed.stderr)}
    log({'event': 'probe_result', **result})
    results.append(result)
    print(json.dumps(result, ensure_ascii=True))
(OUT / 'probe-results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
