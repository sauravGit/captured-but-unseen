# Provenance of the runs

Linux x86-64, Python 3.13, default configuration, harness at the commit that adds this file. Binaries are the
`linux_amd64` release archives from github.com/Asymptote-Labs/agent-beacon/releases, fetched with `harness.py fetch`.
The rule-pack digest is the SHA-256 of the sorted per-file SHA-256 list of the extracted `threat-rules/` directory.

| Run | Date | beacon SHA-256 | beacon-hooks SHA-256 | rule-pack digest |
|---|---|---|---|---|
| v1.3.33 (`results/v1.3.33`) | 12 Oct 2026 | 4f7e82243f15b7f5e142ea96fdf6e43f0a58f2943204b9b8536eee794a420cb6 | dc8a4ed1f68094ce94f7f41a69b2129071fb9fce799ee0f40290c117ac4aa9c4 | 46683f2b204f199adfb0fd20fd3fed827430fc3aa1c1cfdc6d598da561104ce5 |
| v1.3.37 (`results/v1.3.37`, after the paper's cutoff) | 12 Oct 2026 | 2f1312b81f034bfa9656006f894d8f6d5c6e817e1ccc0f853d582b7baa665f89 | 36df0df1a8657edd2a735256b9d3e808f01d7bd2b42a946679896652f0ae96e1 | b3389996068d855d78718144d1a279cce9cbf78db1b01e0ba71aa1bfd16e6a78 |

Both reported 18/33 attacks and 5/15 benign controls with a finding, poll and hooks identical on 48/48 scenarios,
no finding lost against v1.3.33. opentelemetry-hooks v0.15.0 (`results/otel-hooks-0.15.0`) gave the same visibility
counts as v0.14.0 (path 0/24, written content 0/17, tool result 0/43, prompt text 0/5, command 20/20) and the three
fake credentials in command lines were still unmasked with and without `IDE_OTEL_MASK_PROMPTS=true`.

The paper's evaluation cutoff is 9 October 2026 (Beacon v1.3.29, v1.3.31, v1.3.32, 383bd28, v1.3.33; opentelemetry-hooks
0.14.0). The v1.3.37 and 0.15.0 runs are robustness checks.
