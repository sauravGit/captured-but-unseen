# captured-but-unseen

Test harness and raw results for a short paper in preparation, *Captured but Unseen: A Content-Visibility Gap in
Endpoint Security Telemetry for AI Coding Agents*.

The question is a narrow one. Two open-source tools, [Agent Beacon](https://github.com/Asymptote-Labs/agent-beacon)
and [opentelemetry-hooks](https://pypi.org/project/opentelemetry-hooks/), sit on a developer's machine and record what
AI coding agents do. Given attacks that have already been publicly documented, how many does each one catch, and where
does it go blind? This repo runs 48 scripted scenarios through both and keeps the outputs.

## What came out

- Beacon v1.3.29 raised at least one finding on 16 of 33 attack scenarios, and on 5 of 15 benign ones (all five
  from rules that are meant to be broad). Its two collection modes, after-the-fact `claude sync` and live
  `beacon-hooks`, agreed on all 48 scenarios.
- Direct prompt injection (text in the user's prompt) was caught 2 out of 2 times. Indirect injection (instructions
  hidden in a file the agent reads or a page it fetches) was caught 0 out of 4 times. The injected text was in
  Beacon's log, but the rule language had no field a rule could match it on.
- opentelemetry-hooks has no detection rules. By default it records file paths, file contents, tool results and
  prompts only as a length and a hash. Shell commands are the exception: they are recorded in full.

## Disclosure and fixes

Everything below went to the Beacon maintainers as GitHub issues, and each got a draft fix the same day. Status as of
5 October 2026; check the links for anything newer.

| Issue | Fix | What it was |
|---|---|---|
| [#700](https://github.com/Asymptote-Labs/agent-beacon/issues/700) | [#702](https://github.com/Asymptote-Labs/agent-beacon/pull/702), in v1.3.31 | no rule field for tool-result text |
| [#701](https://github.com/Asymptote-Labs/agent-beacon/issues/701) | [#703](https://github.com/Asymptote-Labs/agent-beacon/pull/703), in v1.3.31 | correlation rule depended on step order |
| [#743](https://github.com/Asymptote-Labs/agent-beacon/issues/743) | [#744](https://github.com/Asymptote-Labs/agent-beacon/pull/744), commit `383bd28` | the #702 fix did not work in live `beacon-hooks` mode |

I checked the last one by building Beacon from source at `383bd28` and re-running everything
(`results/383bd28-source-build`): nothing regressed, and live mode now matches after-the-fact mode. At that time the
newest tagged release, v1.3.32, had been built from the commit just before the merge, so it does not contain that
fix.

## Read this before trusting the numbers

- 44 of the 48 scenarios were written by the author and labeled by the author. This is a coverage map, not a
  benchmark. V01 and V02 use payload text copied from [AgentSec-Bench](https://github.com/Santhosraj/AgentSec-Bench)
  (see `THIRD_PARTY_NOTICES.md`); V03 and V04 are shortened versions of the same payloads plus the follow-up steps.
- Nothing here runs a real agent. Each scenario is a scripted session transcript (poll mode) or a sequence of
  Claude Code hook payloads (live mode). It measures whether a tool notices an action, not whether an agent would
  take it.
- Only Claude Code's formats were exercised. Beacon also has adapters for Codex, Cursor and Copilot; those were not tested.
- One machine, Linux x86-64, default configuration.

## Layout

```
scenarios.py        the 48 scenarios (33 attack, 15 benign)
harness.py          fetch / run / summary / diff / otel
results/
  v1.3.29/                  poll.json, hooks.json   (re-run with harness.py)
  v1.3.31/ v1.3.32/         poll.json, hooks.json
  383bd28-source-build/     poll.json, hooks.json
  otel-hooks-0.14.0/        otel.json
```

## Running it

Written and tested on Python 3.12 (Linux x86-64). No packages are needed except for the opentelemetry-hooks part.

```
python3 harness.py fetch v1.3.29                          # Linux x86-64 release into bin/v1.3.29
python3 harness.py run --bin bin/v1.3.29 --out results/my-run
python3 harness.py summary results/my-run
python3 harness.py diff results/v1.3.29 results/my-run
```

To test a source build, build Beacon (needs Go; `make build` in `cli/beacon` builds the hooks binary first), then put
`beacon`, `beacon-hooks` and a copy of the repo's `rules/` directory named `threat-rules` into one folder and pass it
as `--bin`.

```
pip install -r requirements.txt
python3 harness.py otel --out results/my-otel
```

## Notes on the data

- `otel.json` covers 46 of the 48 scenarios. V03 and V04 were added after that run, and when I tried them later the
  tool's end-of-session step stalled for 40 seconds or more, even on plain text. I did not find out why, so those two
  are missing.
- An early version of my live-mode driver put the tool result under the key `output`. Claude Code's documented key is
  `content`. After fixing it I re-ran v1.3.29 with `harness.py` and got identical findings on all 48 scenarios in both
  modes. The v1.3.31, v1.3.32 and source-build results were produced by earlier scripts with the same logic, before
  everything was merged into `harness.py`.
- The scenarios contain fake credentials. The strings are split in the source so secret scanners don't flag them.

## Credits

Written with a lot of help from Claude (Anthropic), working under the author's direction.
Code is MIT licensed. Scenario payloads V01 and V02 come from AgentSec-Bench, also MIT; see `THIRD_PARTY_NOTICES.md`.
