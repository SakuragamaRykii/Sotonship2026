"""Command-line interface.

    python cli.py scrub --mode balanced < in.txt > out.txt          (report → stderr, or --report r.json)
    python cli.py rehydrate --session <ID> < llm_answer.txt > restored.txt
    python cli.py eval --dataset data/test.jsonl --systems presidio,regex,full

`scrub` prints the session id to stderr and saves the session's pseudonym mappings to the local,
gitignored `.sessions/` folder so `rehydrate` can run later in another process. Secrets and other
removed values are never written there. Use --no-save to keep everything in memory only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scrubber import Session  # noqa: E402
from scrubber import rehydrate as _rehydrate  # noqa: E402
from scrubber import scrub as _scrub  # noqa: E402

app = typer.Typer(add_completion=False, help="Local, reversible PII and secret scrubber for LLM prompts.")


def _stdin() -> str:
    return sys.stdin.buffer.read().decode("utf-8")


def _stdout(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.flush()


def _stderr(text: str) -> None:
    sys.stderr.buffer.write((text + "\n").encode("utf-8"))
    sys.stderr.flush()


@app.command()
def scrub(
    mode: str = typer.Option("balanced", help="balanced | strict"),
    report: Path | None = typer.Option(None, help="write the JSON report here instead of stderr"),
    layers: str | None = typer.Option(None, help="comma-separated detector layers, e.g. L1,L2,L3 (default: policy)"),
    session: str | None = typer.Option(None, help="continue an existing session (same surrogates)"),
    no_save: bool = typer.Option(False, "--no-save", help="do not persist the session to .sessions/"),
) -> None:
    """Read text on stdin, write the scrubbed text to stdout."""
    sess = Session.load(session) if session else Session()
    result = _scrub(_stdin(), sess, mode=mode, layers=layers.split(",") if layers else None)
    _stdout(result.scrubbed_text)
    # The report carries offsets, types and reasons, never the original values.
    rep = {
        "session_id": sess.id,
        "report": result.report,
        "spans": [{k: v for k, v in s.model_dump().items() if k != "text"} for s in result.spans],
        "actions": result.actions,  # surrogates and placeholders only
    }
    if report:
        report.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    else:
        _stderr(json.dumps(rep, indent=2))
    if not no_save:
        path = sess.save()
        _stderr(f"session: {sess.id}  (saved to {path})")
    else:
        _stderr(f"session: {sess.id}  (not saved)")


@app.command()
def rehydrate(session: str = typer.Option(..., help="session id printed by `scrub`")) -> None:
    """Read an LLM response on stdin, write it with real values restored to stdout."""
    sess = Session.load(session)
    text, warnings = _rehydrate(_stdin(), sess)
    _stdout(text)
    for w in warnings:
        _stderr(f"warning: {w}")


@app.command("eval")
def eval_(
    dataset: list[Path] = typer.Option(None, help="dataset JSONL (repeatable); default test + held-out"),
    systems: str = typer.Option("raw,presidio,regex,full"),
    modes: str = typer.Option("balanced,strict"),
    utility: bool = typer.Option(False, help="send tasks to the configured LLM (costs API calls)"),
    limit: int | None = typer.Option(None),
    l5: bool = typer.Option(False, help="add the L5 local-LLM layer to `full`"),
) -> None:
    """Run the evaluation harness and write eval/results/results.md + results.csv."""
    from eval.run_eval import main

    argv = ["--systems", systems, "--modes", modes]
    for d in dataset or []:
        argv += ["--dataset", str(d)]
    if utility:
        argv.append("--utility")
    if limit:
        argv += ["--limit", str(limit)]
    if l5:
        argv.append("--l5")
    main(argv)


if __name__ == "__main__":
    app()
