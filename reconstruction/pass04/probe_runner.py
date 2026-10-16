import subprocess, sys, json, datetime, os

EXE = r"C:\HFF\MDI\Dysphasia\artifacts\protected-p1p2p3\PixelTone.exe"
LOG = r"C:\HFF\MDI\Dysphasia\reconstruction\pass04\probe_log.jsonl"

def run_probe(args, note):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    proc = subprocess.run([EXE] + args, capture_output=True)
    rec = {
        "timestamp_utc": ts,
        "note": note,
        "argv": args,
        "exit_code": proc.returncode,
        "stdout_hex": proc.stdout.hex(),
        "stdout_repr": proc.stdout.decode("utf-8", errors="replace"),
        "stderr_hex": proc.stderr.hex(),
        "stderr_repr": proc.stderr.decode("utf-8", errors="replace"),
    }
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    print("ARGS:", args)
    print("EXIT:", proc.returncode)
    print("STDOUT:", rec["stdout_repr"])
    print("STDERR:", rec["stderr_repr"])
    print("----")
    return rec

if __name__ == "__main__":
    note = sys.argv[1]
    args = sys.argv[2:]
    run_probe(args, note)
