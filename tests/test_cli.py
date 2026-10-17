import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = str(ROOT / "cli.py")


def run(args, stdin, cwd):
    p = subprocess.run([sys.executable, CLI, *args], input=stdin.encode("utf-8"), capture_output=True, cwd=cwd)
    assert p.returncode == 0, p.stderr.decode("utf-8", "replace")
    return p.stdout.decode("utf-8"), p.stderr.decode("utf-8")


def test_scrub_then_rehydrate(tmp_path):
    text = '{"name": "Jane Doe", "email": "jane.doe@gmail.com", "token": "sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDf"}'
    out, err = run(["scrub", "--layers", "L1,L2,L3", "--report", "r.json"], text, tmp_path)
    assert "jane.doe@gmail.com" not in out and "Jane Doe" not in out and "sk-proj" not in out
    rep = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert "Jane Doe" not in json.dumps(rep) and "sk-proj" not in json.dumps(rep)
    sid = rep["session_id"]
    assert "sk-proj" not in (tmp_path / ".sessions" / f"{sid}.json").read_text(encoding="utf-8")
    answer = "Person_1 can be reached at user_1@example.com. Person_9 cannot."
    back, err = run(["rehydrate", "--session", sid], answer, tmp_path)
    assert back == "Jane Doe can be reached at jane.doe@gmail.com. Person_9 cannot."
    assert "Person_9" in err
