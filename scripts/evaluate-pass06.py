"""Black-box comparison: artifacts/protected-p1p2p3/PixelTone.exe (current v2 build)
vs reconstruction/pass06/pixel_tone.py. Same corpus/semantics as evaluate-pass0{3,4,5}.py.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(command, args):
    try:
        result = subprocess.run(command + args, cwd=ROOT, capture_output=True, timeout=5)
        return {'exit': result.returncode, 'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex()}
    except subprocess.TimeoutExpired:
        return {'timeout': True}


def main():
    target = ROOT / 'artifacts/protected-p1p2p3/PixelTone.exe'
    clone = ROOT / 'reconstruction/pass06/pixel_tone.py'
    corpus_path = ROOT / 'logs/evaluation01/corpus.json'
    cases = json.loads(corpus_path.read_text(encoding='utf-8'))

    clone_hash_before = digest(clone)
    started = datetime.now(timezone.utc).isoformat()

    rows = []
    for case in cases:
        baseline_result = invoke([str(target)], case['args'])
        clone_result = invoke([sys.executable, str(clone)], case['args'])
        match = baseline_result == clone_result
        rows.append({**case, 'match': match, 'baseline': baseline_result, 'clone': clone_result})

    clone_hash_after = digest(clone)
    if clone_hash_before != clone_hash_after:
        raise RuntimeError('pixel_tone.py changed during evaluation')

    summary = {
        'started_at_utc': started,
        'finished_at_utc': datetime.now(timezone.utc).isoformat(),
        'target_sha256': digest(target),
        'clone_sha256': clone_hash_before,
        'corpus': str(corpus_path.relative_to(ROOT)),
        'case_count': len(rows),
        'passed': sum(r['match'] for r in rows),
        'failed_ids': [r['id'] for r in rows if not r['match']],
        'by_kind': {
            kind: {
                'total': sum(r['kind'] == kind for r in rows),
                'passed': sum(r['kind'] == kind and r['match'] for r in rows),
            }
            for kind in sorted({r['kind'] for r in rows})
        },
    }

    out_dir = ROOT / 'logs/verify-pass06'
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (out_dir / 'cases.jsonl').write_text(
        ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
