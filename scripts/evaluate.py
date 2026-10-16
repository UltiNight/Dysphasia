"""Withheld black-box comparison: fixture executable vs independent reconstructions.

Neither source text nor a formula oracle is used to score a reconstruction.
Concurrent subprocess durations are diagnostic timings, not latency benchmarks.
"""
import concurrent.futures
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def corpus():
    rng = random.Random(20261014)
    cases = []
    for rgb, brightness, contrast, preset in itertools.product(
        [(0, 0, 0), (255, 255, 255), (127, 128, 129), (1, 254, 128), (200, 64, 17)],
        [-100, 0, 100], [0, 99, 100, 200], ['neutral', 'mono', 'warm']
    ):
        cases.append({'kind': 'valid-boundary', 'args': [*map(str, rgb), str(brightness), str(contrast), preset]})
    for _ in range(120):
        cases.append({'kind': 'valid-random', 'args': [
            *(str(rng.randrange(256)) for _ in range(3)), str(rng.randrange(-100, 101)),
            str(rng.randrange(201)), rng.choice(['neutral', 'mono', 'warm'])]})
    cases.append({'kind': 'help', 'args': ['--help']})
    normal = ['64', '128', '200', '10', '125', 'warm']
    for i, values in enumerate([
        ['-1', '256', '1.0', '0x10', '2147483648', '', 'abc', '１２', '١٢', ' 64 ', '+64', '00064', '64\t', '\u00a064'],
        ['-1', '256'], ['-1', '256'], ['-101', '101', '-0', '+0'], ['-1', '201'],
        ['Warm', 'MONO', '', 'unknown', 'warm ']
    ]):
        for value in values:
            args = normal.copy()
            args[i] = value
            cases.append({'kind': 'parser-edge', 'args': args})
    for args in [[], normal[:5], normal + ['extra'], ['--HELP'], ['--help', 'extra']]:
        cases.append({'kind': 'arity-edge', 'args': args})
    return [{'id': i + 1, **case} for i, case in enumerate(cases)]


def invoke(command, args):
    start = time.perf_counter()
    try:
        result = subprocess.run(command + args, cwd=ROOT, capture_output=True, timeout=5)
        return {'exit': result.returncode, 'stdout_hex': result.stdout.hex(),
                'stderr_hex': result.stderr.hex(), 'elapsed_ms': (time.perf_counter() - start) * 1000}
    except subprocess.TimeoutExpired:
        return {'timeout': True, 'elapsed_ms': (time.perf_counter() - start) * 1000}


def observable(result):
    return {key: value for key, value in result.items() if key != 'elapsed_ms'}


def main():
    run_id = sys.argv[1] if len(sys.argv) > 1 else 'evaluation01'
    output = ROOT / 'logs' / run_id
    output.mkdir(parents=True, exist_ok=False)
    cases = corpus()
    (output / 'corpus.json').write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding='utf-8')
    target = ROOT / 'artifacts/baseline/PixelTone.exe'
    clones = {p: ROOT / 'reconstruction' / p / 'pixel_tone.py' for p in ['pass01', 'pass02']}
    for path in clones.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    started = datetime.now(timezone.utc).isoformat()
    clone_hashes = {key: digest(path) for key, path in clones.items()}
    commands = {'baseline': [str(target)], **{key: [sys.executable, str(path)] for key, path in clones.items()}}
    def check(case):
        results = {key: invoke(command, case['args']) for key, command in commands.items()}
        matches = {key: observable(results[key]) == observable(results['baseline'])
                   and 'timeout' not in results['baseline'] for key in clones}
        return {**case, 'results': results, 'matches': matches}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(check, cases))
    (output / 'cases.jsonl').write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
    if clone_hashes != {key: digest(path) for key, path in clones.items()}:
        raise RuntimeError('Reconstruction changed during evaluation')
    summary = {'started_at_utc': started, 'finished_at_utc': datetime.now(timezone.utc).isoformat(),
               'target_sha256': digest(target), 'clone_sha256': clone_hashes, 'python': sys.version,
               'seed': 20261014, 'case_count': len(rows), 'workers': 4,
               'scope': 'Exact stdout bytes, stderr bytes, and exit code; finite corpus, not equivalence proof',
               'results': {key: {'passed': sum(r['matches'][key] for r in rows),
                    'failed_ids': [r['id'] for r in rows if not r['matches'][key]],
                    'by_kind': {kind: {'total': sum(r['kind'] == kind for r in rows),
                        'passed': sum(r['kind'] == kind and r['matches'][key] for r in rows)}
                        for kind in sorted({r['kind'] for r in rows})}} for key in clones}}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
