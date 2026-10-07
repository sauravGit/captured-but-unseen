#!/usr/bin/env python3
"""
Test harness for the "Captured but Unseen" evaluation of endpoint security tools for AI coding agents.

    python3 harness.py fetch v1.3.29                 # download a Beacon release (Linux x86-64) into bin/v1.3.29
    python3 harness.py run --bin bin/v1.3.29 --out results/my-run
    python3 harness.py summary results/my-run        # detection tallies
    python3 harness.py diff results/v1.3.29 results/my-run
    python3 harness.py otel --out results/otel       # what opentelemetry-hooks exposes (needs `pip install -r requirements.txt`)

Standard library only. A --bin directory must contain `beacon`, `beacon-hooks` and a `threat-rules/` directory.
`fetch` produces exactly that; for a source build, copy the two binaries and the repo's `rules/` directory
(as `threat-rules`) into one folder.
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from scenarios import S  # noqa: E402

REPO = "Asymptote-Labs/agent-beacon"

# The six scenarios the original disclosure was about.
FOCUS = {
    "A42": "indirect injection via WebFetch result",
    "A43": "indirect injection via Read result",
    "V01": "AgentSec-Bench injected-notes (read only)",
    "V02": "AgentSec-Bench multi-step-injection (read only)",
    "V03": "injected-notes, full chain (curl|sh, then .env read)",
    "V04": "multi-step-injection, full chain (.env read, then scoped rm -rf)",
}
DIRECT = ["A40", "A41"]
INDIRECT = ["A42", "A43", "V01", "V02"]


# ---------------------------------------------------------------- fetching a release

def resolve_tag(tag):
    if tag != "latest":
        return tag
    req = urllib.request.Request(f"https://github.com/{REPO}/releases/latest", method="HEAD")
    with urllib.request.urlopen(req) as r:
        return r.geturl().rstrip("/").split("/")[-1]


def _extract(archive, dest):
    with tarfile.open(archive) as tf:
        try:
            tf.extractall(dest, filter="data")
        except TypeError:  # older Python without extraction filters
            tf.extractall(dest)


def cmd_fetch(a):
    tag = resolve_tag(a.tag)
    ver = tag.lstrip("v")
    dest = Path(a.dest) if a.dest else ROOT / "bin" / tag
    dest.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/{REPO}/releases/download/{tag}"
    for url, sub in ((f"{base}/beacon_{ver}_linux_amd64.tar.gz", None), (f"{base}/threat-rules.tar.gz", "threat-rules")):
        print("downloading", url)
        tmp = dest / "_download.tgz"
        urllib.request.urlretrieve(url, tmp)
        target = dest / sub if sub else dest
        target.mkdir(parents=True, exist_ok=True)
        _extract(tmp, target)
        tmp.unlink()
    out = subprocess.run([str(dest / "beacon"), "version"], capture_output=True, text=True)
    print(out.stdout.strip() or out.stderr.strip())
    print("ready:", dest)


# ---------------------------------------------------------------- scenario -> input

def build_session(sc):
    """A scenario as a Claude Code session transcript (what `beacon endpoint claude sync` reads)."""
    sid = f"sess-{sc['id']}"
    base = {"isSidechain": False, "cwd": "/work/repo", "sessionId": sid, "version": "2.1.154", "gitBranch": "main"}
    recs, n, parent = [], 0, None

    def add(rec):
        nonlocal n, parent
        n += 1
        u = f"u{n}"
        recs.append(dict(base, parentUuid=parent, uuid=u, timestamp=f"2026-09-28T17:00:{n:02d}.000Z", **rec))
        parent = u

    for st in sc["steps"]:
        if st[0] == "prompt":
            add(dict(type="user", message={"role": "user", "content": st[1]}))
        else:
            _, name, inp, res = st
            tid = f"toolu_{sc['id']}_{n}"
            add(dict(type="assistant", message={
                "id": f"m{n}", "type": "message", "role": "assistant", "model": "claude-sonnet-5",
                "content": [{"type": "tool_use", "id": tid, "name": name, "input": inp}],
                "usage": {"input_tokens": 10, "output_tokens": 5}}))
            add(dict(type="user", message={"role": "user",
                                           "content": [{"type": "tool_result", "tool_use_id": tid, "content": res}]}))
    return sid, recs


def _env(work):
    home = work / "home"
    home.mkdir(parents=True, exist_ok=True)
    return dict(os.environ, HOME=str(home))


def _scan(bindir, log, env):
    r = subprocess.run([str(bindir / "beacon"), "scan", "--log-path", str(log),
                        "--rules", str(bindir / "threat-rules"), "--json"],
                       env=env, capture_output=True, text=True, timeout=60)
    try:
        findings = json.loads(r.stdout) if r.stdout.strip() else []
    except json.JSONDecodeError:
        findings = []
    return sorted({f["rule_id"] for f in (findings or [])})


def _record(sc, fired):
    return dict(label=sc["label"], group=sc["group"], desc=sc["desc"], fired=fired)


def run_poll(bindir, work, scenarios):
    """After-the-fact mode: write a session transcript, `beacon endpoint claude sync`, then `beacon scan`."""
    env, out = _env(work), {}
    for sc in scenarios:
        d = work / "poll" / sc["id"]
        shutil.rmtree(d, ignore_errors=True)
        (d / "projects" / "-work-repo").mkdir(parents=True)
        sid, recs = build_session(sc)
        (d / "projects" / "-work-repo" / f"{sid}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        log = d / "log.jsonl"
        subprocess.run([str(bindir / "beacon"), "endpoint", "claude", "sync",
                        "--projects-dir", str(d / "projects"), "--log-path", str(log),
                        "--state", str(d / "state.json"), "--json"],
                       env=env, capture_output=True, text=True, timeout=60)
        out[sc["id"]] = _record(sc, _scan(bindir, log, env))
    return out


def run_hooks(bindir, work, scenarios):
    """Live mode: feed each step to `beacon-hooks` as Claude Code's hook JSON on stdin, then `beacon scan`."""
    env, out = _env(work), {}
    for sc in scenarios:
        d = work / "hooks" / sc["id"]
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
        log = d / "log.jsonl"
        common = {"session_id": f"hk-{sc['id']}", "transcript_path": str(d / "t.jsonl"), "cwd": "/work/repo"}

        def call(sub, payload):
            subprocess.run([str(bindir / "beacon-hooks"), sub, "--platform", "claude", "--log", str(log)],
                           input=json.dumps(payload), env=env, capture_output=True, text=True, timeout=60)

        call("session-start", dict(common, hook_event_name="SessionStart"))
        for st in sc["steps"]:
            if st[0] == "prompt":
                call("prompt-submit", dict(common, hook_event_name="UserPromptSubmit", prompt=st[1]))
            else:
                _, name, inp, res = st
                call("pre-tool", dict(common, hook_event_name="PreToolUse", tool_name=name, tool_input=inp))
                # Claude Code's hooks reference says tool_response's shape depends on the tool; the harness puts
                # the result under "content", and findings were identical with the earlier "output" key.
                call("post-tool", dict(common, hook_event_name="PostToolUse", tool_name=name,
                                       tool_input=inp, tool_response={"content": res}))
        call("stop", dict(common, hook_event_name="Stop"))
        out[sc["id"]] = _record(sc, _scan(bindir, log, env))
    return out


def _pick(ids):
    if not ids:
        return S
    want = set(ids)
    missing = want - {s["id"] for s in S}
    if missing:
        sys.exit(f"unknown scenario id(s): {sorted(missing)}")
    return [s for s in S if s["id"] in want]


def _write_merged(path, data, merge):
    prev = json.loads(path.read_text()) if (merge and path.exists()) else {}
    prev.update(data)
    path.write_text(json.dumps(prev, indent=1))


def cmd_run(a):
    bindir = Path(a.bin).resolve()
    for need in ("beacon", "beacon-hooks", "threat-rules"):
        if not (bindir / need).exists():
            sys.exit(f"{bindir} is missing '{need}'. See the README for how to populate it.")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    work = ROOT / "work" / out.name
    scenarios = _pick(a.ids)
    modes = [m.strip() for m in a.modes.split(",")]
    if "poll" in modes:
        print(f"poll mode, {len(scenarios)} scenarios ...")
        _write_merged(out / "poll.json", run_poll(bindir, work, scenarios), bool(a.ids))
    if "hooks" in modes:
        print(f"hooks mode, {len(scenarios)} scenarios ...")
        _write_merged(out / "hooks.json", run_hooks(bindir, work, scenarios), bool(a.ids))
    print("wrote", out)


# ---------------------------------------------------------------- reading results

def _load(d, name):
    p = Path(d) / name
    return json.loads(p.read_text()) if p.exists() else None


def cmd_summary(a):
    for mode in ("poll", "hooks"):
        res = _load(a.dir, f"{mode}.json")
        if res is None:
            continue
        attacks = [k for k, v in res.items() if v["label"] == "attack"]
        benign = [k for k, v in res.items() if v["label"] == "benign"]
        hit = [k for k in attacks if res[k]["fired"]]
        fp = [k for k in benign if res[k]["fired"]]
        print(f"\n[{mode}]  scenarios: {len(res)}")
        print(f"  attacks with >=1 finding: {len(hit)}/{len(attacks)}")
        print(f"  benign with >=1 finding:  {len(fp)}/{len(benign)}")
        groups = {}
        for k in attacks:
            g = res[k]["group"]
            groups.setdefault(g, [0, 0])
            groups[g][0] += 1
            groups[g][1] += bool(res[k]["fired"])
        for g, (tot, f) in sorted(groups.items()):
            print(f"    {g:10} {f}/{tot}")
        d = [k for k in DIRECT if k in res]
        i = [k for k in INDIRECT if k in res]
        if d and i:
            print(f"  direct injection detected:   {sum(bool(res[k]['fired']) for k in d)}/{len(d)}   ({', '.join(d)})")
            print(f"  indirect injection detected: {sum(bool(res[k]['fired']) for k in i)}/{len(i)}   ({', '.join(i)})")
    poll, hooks = _load(a.dir, "poll.json"), _load(a.dir, "hooks.json")
    if poll and hooks:
        diffs = [k for k in poll if k in hooks and poll[k]["fired"] != hooks[k]["fired"]]
        print(f"\npoll vs hooks identical on {len(poll) - len(diffs)}/{len(poll)} scenarios", f"(differ: {diffs})" if diffs else "")


def cmd_diff(a):
    for mode in ("poll", "hooks"):
        old, new = _load(a.old, f"{mode}.json"), _load(a.new, f"{mode}.json")
        if old is None or new is None:
            continue
        print(f"\n=== {mode}: {a.old} -> {a.new} ===")
        gained, lost = [], []
        for k in sorted(new):
            o, n = set(old.get(k, {}).get("fired", [])), set(new[k]["fired"])
            if n - o:
                gained.append((k, sorted(n - o)))
            if o - n:
                lost.append((k, sorted(o - n)))
        print("lost a finding (regression):", lost or "none")
        print("gained a finding:", gained or "none")
        print("the six disclosure scenarios:")
        for k, why in FOCUS.items():
            if k in new:
                print(f"  {k}  {why}\n      before {sorted(old.get(k, {}).get('fired', []))}\n      after  {sorted(new[k]['fired'])}")


# ---------------------------------------------------------------- opentelemetry-hooks

def _flat(o, out):
    if isinstance(o, dict):
        for v in o.values():
            _flat(v, out)
    elif isinstance(o, list):
        for v in o:
            _flat(v, out)
    else:
        out.append(str(o))


def cmd_otel(a):
    exe = shutil.which("otel-hook")
    if not exe:
        sys.exit("otel-hook not found on PATH. Run: pip install -r requirements.txt")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    work = ROOT / "work" / "otel-home"
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(work / "home"), IDE_OTEL_HOOK_HOME=str(work),
               IDE_OTEL_LOCAL_SPANS="true", IDE_OTEL_BATCH_ON_STOP="true", IDE_OTEL_IDE_NAME="claude",
               OTEL_TRACES_EXPORTER="none", OTEL_LOGS_EXPORTER="none", IDE_OTEL_DISABLE_BATCH="1")
    # An inherited TRACEPARENT with the sampled flag off makes the hook record no spans at all.
    for k in ("IDE_OTEL_CAPTURE_TEXT", "IDE_OTEL_DEBUG_CONSOLE", "TRACEPARENT", "TRACESTATE"):
        env.pop(k, None)
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    # On first run the hook writes a config that points at http://localhost:4317. With nothing listening,
    # the Stop hook stalls for 40s or more. Seed a config with no endpoint so only local spans are written.
    import importlib.metadata as _md
    _ex = [f for f in (_md.files("opentelemetry-hooks") or []) if f.name == "otel_config.example.json"]
    if _ex:
        cfg = json.load(open(_ex[0].locate()))
        cfg["OTEL_EXPORTER_OTLP_ENDPOINT"] = None
        cfg["IDE_OTEL_ENABLE_LOGS"] = "false"
        (work / "otel_config.json").write_text(json.dumps(cfg))

    def call(payload):
        subprocess.run([exe], input=json.dumps(payload), env=env, capture_output=True, text=True, timeout=240)

    results = {}
    for sc in _pick(a.ids):
        shutil.rmtree(work / ".state", ignore_errors=True)
        common = {"session_id": f"ot-{sc['id']}", "cwd": "/work/repo", "transcript_path": "/tmp/t.jsonl"}
        call(dict(common, hook_event_name="SessionStart"))
        needles = {}
        for st in sc["steps"]:
            if st[0] == "prompt":
                needles["prompt_text"] = st[1][:40]
                call(dict(common, hook_event_name="UserPromptSubmit", prompt=st[1]))
            else:
                _, name, inp, res = st
                if "file_path" in inp:
                    needles["path"] = inp["file_path"]
                if "command" in inp:
                    needles["command"] = inp["command"]
                if "content" in inp:
                    needles["written_content"] = inp["content"][:30]
                needles["tool_result"] = res[:30]
                call(dict(common, hook_event_name="PreToolUse", tool_name=name, tool_input=inp))
                call(dict(common, hook_event_name="PostToolUse", tool_name=name, tool_input=inp,
                          tool_response={"content": res}))
        call(dict(common, hook_event_name="Stop"))
        vals, nspans = [], 0
        for f in glob.glob(str(work / ".state" / "local_spans" / "*.jsonl")):
            for line in open(f, encoding="utf-8"):
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                nspans += 1
                _flat(o, vals)
        blob = "\n".join(vals)
        results[sc["id"]] = dict(label=sc["label"], group=sc["group"], desc=sc["desc"], spans=nspans,
                                 visible={k: (v in blob) for k, v in needles.items()})
        print(sc["id"], results[sc["id"]]["visible"])
    _write_merged(out / "otel.json", results, bool(a.ids))
    print("wrote", out / "otel.json")


# ---------------------------------------------------------------- CLI

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="download a Beacon release (Linux x86-64)")
    f.add_argument("tag", help="e.g. v1.3.29, or 'latest'")
    f.add_argument("--dest")
    f.set_defaults(fn=cmd_fetch)
    r = sub.add_parser("run", help="run the scenarios against a Beacon build")
    r.add_argument("--bin", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--modes", default="poll,hooks")
    r.add_argument("--ids", nargs="*", help="only these scenario ids (results are merged into existing files)")
    r.set_defaults(fn=cmd_run)
    s = sub.add_parser("summary", help="print detection tallies for a results directory")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_summary)
    d = sub.add_parser("diff", help="compare two results directories")
    d.add_argument("old")
    d.add_argument("new")
    d.set_defaults(fn=cmd_diff)
    o = sub.add_parser("otel", help="measure what opentelemetry-hooks exposes")
    o.add_argument("--out", required=True)
    o.add_argument("--ids", nargs="*")
    o.set_defaults(fn=cmd_otel)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
