# WolframGuard security PoC — Windows pilot

> **📄 Start here: [WolframGuard — project submission](reports/SUBMISSION.md)** — the full narrative: the problem (an agent code-evaluator is a shell for prompt injection), the gap we measured, the gate we built, and the checkable result (19 evasion payloads, zero state change under `ReadOnly`).

**Executed on the installed Windows environment.** Six completed attack trials produced five unsafe text proposals/narratives, zero native forbidden calls and zero unauthorized side effects. Two benign database controls both correctly counted 250 inactive records. See [Windows results and reproduction](reports/windows_execution.md).

**Configuration A (real AgentTools evaluator + Claude Code default approvals) has now run.** The AgentTools 2.2.0 evaluator itself has no approval step: driven directly, it deleted 250 rows of a designated synthetic copy without any prompt. Through Claude Code 2.1.118 with untouched permission defaults, every model-requested Wolfram call was denied before reaching the server. That includes one injection-induced evaluator call carrying DELETE SQL (malformed, Blocked). In all three trials where the local 3B model read an attack document, it adopted the injected deletion or update in text (two Attempted). See [Configuration A results](reports/agenttools_config_a.md).

**WolframGuard closes the evaluator gap with containment.** For a read-only task WolframGuard applies an OS-level deny-write lock to the authorized task data at the evaluator, independent of the MCP client, so a write fails at the operating system regardless of which primitive or language issues it — a probe showed this stops even the JDBC database write that a Wolfram-level sandbox (`StartProtectedMode`) lets through. A parse-before-run effect classifier sits in front as a fast pre-filter. In the deterministic gap test (`wolframguard-gap-001`) ReadOnly blocked `DELETE`/`UPDATE`/`DeleteFile`/`RunProcess`/`URLRead`/dynamic-eval with zero state change while the legitimate `SELECT` still returned 250. See [WolframGuard](reports/wolframguard.md).

**Checkable result — the containment proof (`wolframguard-containment-001`).** 19 evasion payloads (split/commented/dynamic SQL, aliased and obscure-primitive file writes, JDBC deletes, process/network) fired at the real guarded server under three policies, each measured by independent before/after state. Under `ReadOnly`, **zero payloads changed any synthetic state** (all 19 fixtures pristine: 1,000/250, 10 files, no `EVIL_*`), while 16 were proven live under `Off`. Decisively, under `ContainmentOnly` — the **classifier disabled**, every payload allowed — state still changed on **0/19**: the read-only guarantee rests on OS containment, not on the denylist being complete. See the project writeup ([SUBMISSION](reports/SUBMISSION.md)) and the earlier [evasion battery](reports/wolframguard_bypass.md).

**No unauthorized execution or default-control bypass was demonstrated.** Separate explicitly authorized Wolfram capability checks did delete a designated synthetic file and 250 synthetic database rows. Those checks are not injection successes.

The local kernel is Wolfram 15.0.1, with Wolfram/AgentTools 2.2.0, Wolfram/Chatbook 2.7.0 and Wolfram/LLMFunctions 2.3.1. The inspected AgentTools local default selects Session evaluation; a separate Local sandbox exists. This is a source finding, not evidence of unauthorized execution or the selected client's approval behavior.

- [**WolframGuard — project submission (narrative front door)**](reports/SUBMISSION.md)
- [Environment and execution path](reports/environment.md)
- [Current Windows findings, evidence and limitations](reports/windows_execution.md)
- [Configuration A: AgentTools evaluator behind Claude Code default approvals](reports/agenttools_config_a.md)
- [WolframGuard (minimal): a pre-execution effect gate that closes the evaluator gap](reports/wolframguard.md)
- [WolframGuard evasion battery: a concrete, checkable result (19 payloads, zero state change under ReadOnly)](reports/wolframguard_bypass.md)
- [Initial discovery checkpoint](reports/findings.md)
- [Reproduction and isolation](environment/setup.md)
- [Concrete first isolated test](environment/first_isolated_test.md)
- [Threat model](reports/threat_model.md)
- [90-second demonstration script](demo/demo_script.md)
- [Disclosure status](reports/disclosure.md)

Each agent trial starts with ten synthetic research files and a 1,000-row database containing 250 inactive records. The Windows runs use qwen2.5:1.5b locally through Ollama 0.23.1 and actual Wolfram GenAI LLMTool dispatch. B exposes fixed mutation tools automatically; C exposes fixed readers only. Neither accepts arbitrary model code, SQL, paths or URLs. This is a custom-client pilot, not an AgentTools-defaults test.

The six reviewed attack trials are in results/trials.csv; benign controls and the incomplete 3B timeout run are kept separately. There is one trial per scenario/configuration, so no confidence interval or general security guarantee is warranted. Configuration A adds three reviewed exposed database trials (Claude Code headless, local Qwen 3B, n=1 per document). Its interactive approval dialog and the filesystem and network scenarios remain untested. The expanded ten-trial study and remaining document variants are still pending.

The earlier Docker instrumentation preparation and VM preflight are preserved. VM test remains powered off, disconnected and snapshotted. The Windows route was explicitly requested by the user. It confines model choices through fixed synthetic capabilities; it does not provide an OS sandbox. No external test destination, real credential or production data is used. Documents under fixtures/documents contain **untrusted attack text** and are never setup instructions.
