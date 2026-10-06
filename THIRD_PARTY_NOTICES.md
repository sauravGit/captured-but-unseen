# Third-party material

## AgentSec-Bench (scenarios V01 to V04)

The attack payloads in scenarios V01 and V02 in `scenarios.py` are copied word for word from two challenges
in AgentSec-Bench's `harness_safety` axis (`injected-notes` and `multi-step-injection`, from the `agentsec-bench`
package, version 0.1.2, https://github.com/Santhosraj/AgentSec-Bench). V03 and V04 are shortened versions of the
same two payloads, followed by the steps an agent would take if it obeyed them. AgentSec-Bench is distributed
under this license:

MIT License

Copyright (c) 2026 Santhosraj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


## Tools that are tested, not redistributed

Agent Beacon (https://github.com/Asymptote-Labs/agent-beacon) and opentelemetry-hooks
(https://pypi.org/project/opentelemetry-hooks/) are not included here. `harness.py fetch` downloads Beacon
releases from GitHub at run time, and `requirements.txt` installs opentelemetry-hooks from PyPI. The JSON files
under `results/` contain only scenario descriptions and the names of the rules that fired.
