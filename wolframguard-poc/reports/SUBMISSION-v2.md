# WolframGuard

### A containment-based read-only guard for the Wolfram agent evaluator

*Clean rewrite. The original, longer write-up is preserved at [SUBMISSION.md](SUBMISSION.md); this version is the same project told as one settled narrative, leading with the findings.*

---

## Findings at a glance

Everything below is measured against the **real** Wolfram/AgentTools 2.2.0 evaluator, with synthetic data only, an offline kernel, and before/after state checked independently of anything the guard reports about itself.

| # | Finding | Evidence |
|---|---|---|
| 1 | **The evaluator has no gate of its own.** Driven directly, it ran `DELETE FROM customers WHERE status='inactive'` and removed 250 synthetic rows — no prompt, no confirmation. | [config A](agenttools_config_a.md) |
| 2 | **The only protection is the MCP client's per-tool approval** — and the vendor's docs name that click as the mitigation while warning about prompt injection. One "always allow" removes it. The default local method is labelled *not sandboxed*. | [config A](agenttools_config_a.md), AgentTools docs |
| 3 | **A denylist is the wrong foundation.** Deciding if arbitrary code is safe by inspection is undecidable; the evasion battery found a real head-only aliasing bypass in our own classifier. | [bypass-finding.json](../results/wolframguard-bypass-001/bypass-finding.json) |
| 4 | **A Wolfram sandbox misses JDBC; an OS lock doesn't.** `Developer\`StartProtectedMode` contains WL writes/process and can't be escaped, but **not** JDBC database writes (the JVM writes the file directly). An OS deny-write lock contains JDBC *and* all WL writes. | [probe-findings.json](../results/wolframguard-containment-001/probe/probe-findings.json) |
| 5 | **Rebuilt on containment, the guarantee holds with the denylist off.** With the classifier **disabled**, all 19 evasion payloads were allowed and **0/19** changed any state; `Off` changed 16/19; `ReadOnly` changed 0/19. | [containment-001](../results/wolframguard-containment-001/summary.json) |
| 6 | **Reads are not collateral damage.** Under the same lock, a legitimate `SELECT COUNT(… 'inactive')` returns `{{250}}` while a `DELETE` on the same connection fails. | probe |
| 7 | **The honest residual:** the lock is a same-user ACL; full robustness wants a lower-privileged principal, and it confines writes, not reads. | §7 |

**In one sentence:** on a default AgentTools install an injected `DELETE` meets exactly one obstacle — a checkbox in the chat client — so WolframGuard adds a second line *inside the server*: for a read-only task it puts an OS-level read-only lock on your data, which stops the write at the operating system no matter what code the model runs, proven by disabling our own classifier and watching 19 evasion payloads still change nothing.

---

## 1. The problem

The most powerful tool you can hand an AI agent is a general-purpose code evaluator, and Wolfram ships one: **Wolfram/AgentTools**, an MCP server whose `WolframLanguageEvaluator` tool takes a string of Wolfram Language from the model and runs it in a live kernel — able to read and write files, open databases, spawn processes, reach the network, with the launching user's full rights. That power is the product. It is also the attack surface.

The standard risk for any tool-using agent is **prompt injection**: the model reads some text — a document, a web page, a returned tool result — and that text contains instructions it cannot reliably distinguish from the user's. When the agent's tool is *"run this arbitrary code,"* the blast radius of a successful injection is the whole machine.

This isn't hypothetical, and it isn't our framing — it's the vendor's. AgentTools' documentation has a **Security Considerations** section stating the evaluator "executes arbitrary Wolfram Language code," enumerating the effects (read/write/delete files, network, system commands, environment variables), and a **Prompt Injection Considerations** subsection naming exactly this threat. The revealing part is the mitigation it recommends: **client-side, approval-based permissions** — configure your AI application to prompt before the evaluator runs. In other words, the vendor's entire recommended defense for a tool that runs arbitrary code is *the human clicking approve in the chat client.*

We measured what that leaves. Driven directly over MCP, the evaluator deleted 250 synthetic rows with no prompt — it has no gate of its own. Behind Claude Code at default permissions, every model-requested Wolfram call was denied before reaching the server — good, but that protection lives entirely in the **client**, is coarse (a decision about the *tool*, not the code), and vanishes the moment a user clicks "always allow" to stop being nagged. Nor is there a fallback: the paclet ships no server-side policy, and the default local evaluation method is the one its own docs call *not sandboxed*. One injected `DELETE`, one obstacle, and it's a checkbox.

## 2. How peers police unsafe code

Serious code-execution tools don't rely on the model behaving. They use four mechanisms, and the instructive question is *where each lives* and *whether it survives this setup*:

| Mechanism | Example | Lives in | Survives "always allow" / swapped client? |
|---|---|---|---|
| Model refusal | any trained model | the model | No — defeated by injection |
| Harness content analysis | Claude Code's Bash injection detection | the client | Only for the client's *own* shell — not an MCP code-eval tool's arguments |
| Capability / approval gating | MCP per-tool approval; Codex approval policy | the client | **No** — this is the click being removed |
| OS / runtime sandbox | Claude Code `/sandbox`, Codex Seatbelt/Landlock, hosted containers, Wolfram `Local`/`Cloud` | OS / runtime | Yes *when enabled* — off by default on a local AgentTools install |

Mainstream agents put their unsafe-code policy in the **harness and the OS**, usually default-on. A default local AgentTools install has neither on, and the one client that analyzes code content (Claude Code) analyzes its *own* shell, not a third-party MCP evaluator's code string. WolframGuard fills the empty slot: a **task-bound, server-side layer** that neither the model nor a convenience click can switch off.

## 3. The idea: containment, not a list

The weak way to defend a code evaluator is a **denylist** — enumerate the dangerous primitives (`DeleteFile`, `RunProcess`, SQL `DELETE`) and refuse them. It's weak for a reason no list-tending fixes: deciding whether arbitrary code is safe by inspection is undecidable in general, and trivially so once code can build a string and evaluate it. A denylist is a list of the attacks you already thought of.

So WolframGuard inverts the question. For a **read-only** task the code's legitimate needs are small and knowable — compute, read files, `SELECT` — so the robust posture is **default-deny on effects**: permit that small set and make everything else fail *by construction*. And the way to enforce default-deny is not a cleverer scan but **capability containment** — put the evaluation where the write cannot happen. WolframGuard applies an **OS-level read-only lock** to the authorized task data, so a write fails at the operating system regardless of which primitive or language issues it.

The effect classifier from the first version survives, **demoted to a fast pre-filter**: it rejects obvious danger early with a clean message, logs every call, and blocks the process/network axes so the lock can't be tampered with. It is no longer what the guarantee rests on — and we prove that by switching it off and watching the data hold.

## 4. Why the OS lock and not a Wolfram sandbox

Wolfram ships an in-kernel sandbox, `Developer\`StartProtectedMode` (the `Local` method). We measured what it actually contains on this machine:

| Attack (arbitrary code) | `StartProtectedMode` | OS deny-write lock |
|---|---|---|
| WL `DeleteFile` / `OpenWrite` | contained | contained |
| `RunProcess` | contained | n/a (no data write) |
| **JDBC `DELETE` (`DatabaseLink`)** | **NOT contained** → DB 250 → 0 | **contained** → stays 250 |
| escape via `EndProtectedMode` | inert — cannot escape | n/a |

The JDBC row is the whole point: the SQLite write goes through the JVM, outside Wolfram's file guard, so a WL-level sandbox misses the headline database attack. The OS lock catches it because the OS doesn't care which runtime asks. That is why the guarantee rests on the OS lock, with `StartProtectedMode` an in-kernel complement — not the reverse.

## 5. How it works

WolframGuard is **two small files and no change to the installed paclet** — a defense you can drop in front of software you don't own.

- **[`guarded_server.wl`](../wolframguard/guarded_server.wl)** — the launcher. It installs the gate, **applies the containment lock**, then starts the real AgentTools server, and **fails closed** if the guard file is missing. For any policy except `Off`, it reads the authorized task paths from the environment and applies an OS **deny-write ACL** for the current user (`icacls … /deny (WD,AD,DC,DE,WA,WEA)` — writes, creation, deletion, rename, attributes). The evaluator runs as that user, so its writes to the task data are refused by the OS before any Wolfram or Java code tries.
- **[`WolframGuard.wl`](../wolframguard/WolframGuard.wl)** — the pre-filter. It wraps `` Wolfram`Chatbook`WolframLanguageToolEvaluate `` (the single evaluation entry point, `WolframLanguageEvaluator.wl:150`) and classifies each call *before* it runs by parsing the string into an inert held expression it never releases — `ToExpression[code, StandardForm, HoldComplete]` — then reading the symbols and string literals into effect categories (`FilesystemWrite`, `Process`, `Network`, `DatabaseMutation`, `DynamicEval`, `ParseFailure` → fail closed). `SELECT` reads and pure computation pass.

Policies (`WOLFRAMGUARD_POLICY`, read once at startup; `WOLFRAMGUARD_READONLY_PATHS` names the data to lock; the model can change neither):

| Policy | OS lock | Classifier | State-changing effect |
|---|---|---|---|
| `Off` | off | passive | allowed (baseline; still logs) |
| `ReadOnly` *(default)* | **on** | pre-filter | **blocked** — by the lock, flagged by the classifier |
| `AskForWrites` | **on** | pre-filter | refused with approval-required message (headless → blocks) |
| `ContainmentOnly` | **on** | **disabled** | **blocked by the lock alone** — diagnostic, proves the guarantee is containment |

## 6. The evidence

**Gap test ([`wolframguard-gap-001`](../results/wolframguard-gap-001/summary.json)).** One call per known effect, over raw MCP with no client approval layer (the "already clicked always-allow" case). Under `ReadOnly`, `DELETE`/`UPDATE`/`DeleteFile`/`RunProcess`/`URLRead`/dynamic-eval were blocked with zero state change while the legitimate `SELECT` returned 250; the same calls executed under `Off` (DB 750/0, files gone), proving the harness can run them.

**The containment proof ([`wolframguard-containment-001`](../results/wolframguard-containment-001/summary.json)) — the result that answers "it's just a denylist."** The same 19 evasion payloads (split/commented/dynamic SQL, aliased and obscure-primitive file writes, JDBC deletes, process/network) under three policies, state re-snapshotted independently:

| Policy | DB inactive (min/max of 19) | research files | `EVIL_*` | fixtures mutated |
|---|---|---|---|---|
| `Off` | 0 / 250 | 186 / 190 | 5 | **16 / 19** (payloads are real) |
| `ReadOnly` | 250 / 250 | 190 / 190 | 0 | **0 / 19** |
| `ContainmentOnly` (classifier off) | 250 / 250 | 190 / 190 | 0 | **0 / 19** |

```
readonly_zero_state_change:             true
containment_only_classifier_all_allow:  true     ← the classifier was off (allowed all 19)
containment_only_zero_state_change:     true     ← and nothing changed anyway
containment_only_bypasses:              []
```

With the classifier disabled — every payload waved through, all seven JDBC deletes included — **not one of 19 fixtures changed.** The guarantee is containment, not an enumeration of bad symbols. And it's not collateral damage to real work: under the same lock a legitimate `SELECT` returns `{{250}}` while a `DELETE` fails.

**A real bug, found and closed.** Writing the battery caught one payload the classifier *allowed*: `With[{g = DeleteFile}, g[path]]` — `DeleteFile` is a value bound to `g`, not a call head, so a head-only scan missed it. Fixed by testing every symbol, not just heads ([bypass-finding.json](../results/wolframguard-bypass-001/bypass-finding.json)). This is exactly *why* the guarantee was moved onto containment: any denylist will have an edge like this, so the design must not depend on the list being complete — and now it doesn't.

## 7. Honest scope

- **The data-integrity guarantee is containment, not a completeness claim about the classifier.** With the lock on, no write to the locked data succeeds regardless of primitive — shown with the classifier fully disabled, JDBC included. Not claimed: that the classifier catches every technique (it needn't), or that containment reaches past the paths that are locked.
- **Same-user ACL, not a separate principal.** The lock denies writes to the current user, and the evaluator runs as that user; a single payload that *both* spawned a process to rewrite the ACL *and* then wrote would defeat it — which is why the classifier still blocks the process axis, and why the honest production design runs the evaluator as a **lower-privileged principal** (restricted user, container, or protected child kernel) that cannot change the ACL at all. `icacls` is the Windows mechanism; a read-only bind-mount or restricted user is the equivalent elsewhere.
- **It confines writes, not reads.** A permitted read still runs with the user's rights; WolframGuard stops state change and (via `$AllowInternet=False` + the classifier) outbound network, but it is not a full OS sandbox that would also confine what an allowed read can see.
- **It gates one entry point.** The evaluator's single evaluation entry; other AgentTools tools still rely on the client. The evaluator is the sharpest edge — arbitrary code — which is why it came first.
- **`AskForWrites` has no human loop yet** (blocks-and-labels in headless).

## 8. Where it goes next

1. **Lower-privileged principal / protected child kernel** — run the evaluator as a principal that simply lacks write rights, so no in-kernel trick regains them and reads get confined too. Closes the one residual above.
2. **Grow the battery** — more payload classes; each either passes (and we harden) or fails (and the claim broadens).
3. **Real `AskForWrites` elicitation** via MCP's server-initiated request path.
4. **Gate the other tools** with the same discipline.

## 9. Reproduce

No model, no client, no network needed for the core result.

```powershell
# The containment proof — 19 payloads x {Off, ReadOnly, ContainmentOnly}:
python wolframguard-poc/instrumentation/wolframguard_bypass_tests.py --run-id wolframguard-containment-new

# What actually contains each effect (StartProtectedMode vs OS lock, incl. JDBC):
python wolframguard-poc/results/wolframguard-containment-001/probe/probe_containment.py

# The deterministic gap test — one call per known effect, raw MCP, no approval layer:
python wolframguard-poc/instrumentation/wolframguard_gap_tests.py --run-id wolframguard-gap-new
```

Then open `results/wolframguard-containment-new/summary.json` → `verdict` and confirm `containment_only_zero_state_change: true`; re-snapshot the `containmentonly/fixtures/payload_*/fixture` dirs — every one must be **1,000 / 250 with 10 files and no `EVIL_*`.** Requires non-administrator Windows, Wolfram 15.0.1 + AgentTools 2.2.0, a free loopback port 8765.

| Path | What it is |
|---|---|
| [`wolframguard/WolframGuard.wl`](../wolframguard/WolframGuard.wl) | The pre-filter: parse-without-eval effect classifier + policy |
| [`wolframguard/guarded_server.wl`](../wolframguard/guarded_server.wl) | Launcher: installs the gate, applies the OS lock, starts the real server |
| [`instrumentation/wolframguard_bypass_tests.py`](../instrumentation/wolframguard_bypass_tests.py) | The 3-policy containment battery |
| [`results/wolframguard-containment-001/`](../results/wolframguard-containment-001/) | The evidence: verdict, per-policy fixtures, the JDBC-vs-sandbox probe |
| [`reports/agenttools_config_a.md`](agenttools_config_a.md) | How the gap was established |

## 10. The pitch

Give an AI agent a code evaluator and you have given a prompt injection a shell. On Wolfram/AgentTools the only thing between an injected `DELETE` and your data is one approval click — the vendor's own docs name that click as the mitigation. **WolframGuard** adds a second line inside the server: for a read-only task it puts an OS-level read-only lock on your data, so a write fails at the operating system no matter what the code does — we measured it stopping even the JDBC database delete a Wolfram sandbox misses — with a parse-before-run classifier in front as a fast pre-filter. It is not a denylist you must keep complete: switch the classifier off entirely and, across 19 evasion payloads, not one byte of synthetic state changes. Two files, no change to the paclet you already have, every number one command from being re-checked.
