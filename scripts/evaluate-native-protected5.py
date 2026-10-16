"""Black-box comparison: artifacts/baseline/PixelTone.exe (.NET) vs
artifacts/native-protected5/PixelTone.exe (native C, P2+P3+loop-unrolling+pointer-
aliasing+exception-routing plus anti-debugging via a dynamically-resolved
IsDebuggerPresent).

Confirms fixture/PixelTone.protected5.c's is_debugger_present_dynamic (false for every
corpus case, since these are plain subprocess runs, never under a debugger) doesn't
change observable behavior versus the managed baseline (same corpus as evaluate-
native.py / evaluate-native-protected*.py).
"""
import hashlib
import json
import subprocess
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
    managed = ROOT / 'artifacts/baseline/PixelTone.exe'
    native = ROOT / 'artifacts/native-protected5/PixelTone.exe'
    corpus_path = ROOT / 'logs/evaluation01/corpus.json'
    cases = json.loads(corpus_path.read_text(encoding='utf-8'))

    started = datetime.now(timezone.utc).isoformat()
    rows = []
    for case in cases:
        managed_result = invoke([str(managed)], case['args'])
        native_result = invoke([str(native)], case['args'])
        match = managed_result == native_result
        rows.append({**case, 'match': match, 'managed': managed_result, 'native_protected5': native_result})

    summary = {
        'started_at_utc': started,
        'finished_at_utc': datetime.now(timezone.utc).isoformat(),
        'managed_sha256': digest(managed),
        'native_protected5_sha256': digest(native),
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

    out_dir = ROOT / 'logs/verify-native-protected5'
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (out_dir / 'cases.jsonl').write_text(
        ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
