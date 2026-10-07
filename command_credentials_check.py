"""Do credentials in shell commands survive in opentelemetry-hooks spans?

Feeds three fake credentials, as Bash commands, to `otel-hook` and looks for them in the local span files,
with and without IDE_OTEL_MASK_PROMPTS=true. Needs `pip install -r requirements.txt`. Standard library only.
Usage: python3 command_credentials_check.py
"""
import glob, json, os, shutil, subprocess, sys, tempfile

PW = "S3cr3t" + "Pass"
GH = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
AWS = "AKIA" + "IOSFODNN7EXAMPLE"  # the example key from AWS's own documentation
CMDS = [f"curl -u admin:{PW} https://internal.example/api",
        f"export GITHUB_TOKEN={GH} && git push",
        f"aws s3 ls --access-key {AWS}"]


def run(mask):
    exe = shutil.which("otel-hook") or sys.exit("otel-hook not on PATH")
    work = tempfile.mkdtemp()
    env = dict(os.environ, HOME=work + "/home", IDE_OTEL_HOOK_HOME=work, IDE_OTEL_LOCAL_SPANS="true",
               IDE_OTEL_BATCH_ON_STOP="true", IDE_OTEL_IDE_NAME="claude", IDE_OTEL_DISABLE_BATCH="1",
               OTEL_TRACES_EXPORTER="none", OTEL_LOGS_EXPORTER="none")
    for k in ("TRACEPARENT", "TRACESTATE"):  # an inherited unsampled parent makes the hook record nothing
        env.pop(k, None)
    if mask:
        env["IDE_OTEL_MASK_PROMPTS"] = "true"
    os.makedirs(env["HOME"])
    # The hook's generated config points at localhost:4317; with no listener Stop stalls, so start without one.
    import importlib.metadata as md
    ex = [f for f in md.files("opentelemetry-hooks") if f.name == "otel_config.example.json"][0]
    cfg = json.load(open(ex.locate()))
    cfg["OTEL_EXPORTER_OTLP_ENDPOINT"] = None
    cfg["IDE_OTEL_ENABLE_LOGS"] = "false"
    json.dump(cfg, open(work + "/otel_config.json", "w"))
    c = {"session_id": "cred-test", "cwd": "/work/repo", "transcript_path": "/tmp/t.jsonl"}

    def call(p):
        subprocess.run([exe], input=json.dumps(p), env=env, capture_output=True, text=True, timeout=240)
    call(dict(c, hook_event_name="SessionStart"))
    for cmd in CMDS:
        call(dict(c, hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd}))
        call(dict(c, hook_event_name="PostToolUse", tool_name="Bash", tool_input={"command": cmd},
                  tool_response={"content": "ok"}))
    call(dict(c, hook_event_name="Stop"))
    blob = "".join(open(f).read() for f in glob.glob(work + "/.state/local_spans/*.jsonl"))
    shutil.rmtree(work, ignore_errors=True)
    return blob


for mask in (False, True):
    blob = run(mask)
    print(f"IDE_OTEL_MASK_PROMPTS={'true' if mask else 'unset'}: spans written={bool(blob)}",
          {n: (v in blob) for n, v in (("password", PW), ("github_token", GH), ("aws_key_id", AWS))})
