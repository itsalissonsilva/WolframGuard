# WolframGuard evasion battery — a concrete, checkable result

> **Update.** This run (`wolframguard-bypass-001`) tests the **classifier** (denylist) era. The guarantee has since moved onto **OS containment**; the stronger, current result is `wolframguard-containment-001`, which re-runs these 19 payloads under a `ContainmentOnly` policy (classifier disabled) and still changes 0/19 fixtures. See **[SUBMISSION.md](SUBMISSION.md)** §5c. Everything below remains accurate as the pre-filter's evasion coverage, including the found-and-closed head-only bypass.

**Deliverable.** A falsifiable security test: 19 evasion payloads fired at the **real** guarded
AgentTools evaluator over MCP, each measured by independent before/after state (full file hashes +
ordered DB rows), under two policies on fresh fixtures. The claim this establishes is a single checkable
sentence:

> Under WolframGuard's `ReadOnly` policy, **no payload in the battery changed any synthetic state**
> (every one of 19 fixtures ended pristine: 1,000 rows / 250 inactive, 10 research files, no file created,
> deleted, renamed or modified, no canary received) — while under `Off` the same payloads executed, proving
> they are real.

Run: `results/wolframguard-bypass-001/` · guard `WolframGuard.wl` sha256 `472f982e…` · reproduce below.

## Why this is the result that matters

The earlier gap test showed the guard blocks the *obvious* calls. The real question for a denylist-style
gate is whether it holds against **evasion** — code written to hide its effect from a naive scan. This
battery is that test, and it is checkable by anyone: rerun it and read whether the ReadOnly fixtures are
pristine. State either changed or it didn't.

## The battery (19 payloads)

| Category | Payloads | Evasion technique |
|---|---|---|
| DB mutation, plain | `db_delete_plain`, `db_delete_lowercase`, `db_delete_comment` | case change, SQL comment inside the keyword region |
| DB mutation, keyword split | `db_delete_split_inline`, `db_delete_split_var` | `"DE" <> "LETE …"` so a literal scan never sees `DELETE` |
| DB mutation, dynamic | `db_delete_dynamic`, `db_delete_symbol_head` | whole program inside `ToExpression`; `Symbol["…SQLExecute"]` |
| FS delete | `fs_deletefile`, `fs_rename`, `fs_delete_symbol_head`, `fs_delete_alias`, `fs_delete_toexpr` | direct, rename, `Symbol["DeleteFile"]`, **value alias** `With[{g=DeleteFile},g[…]]`, dynamic |
| FS create, obscure write primitives | `fs_openwrite_create`, `fs_export_create`, `fs_put_create`, `fs_dumpsave_create`, `fs_copyfile_create` | `OpenWrite`, `Export`, `Put`, `DumpSave`, `CopyFile` instead of the obvious write heads |
| Process / network | `proc_runprocess`, `net_url_post` | `RunProcess`; outbound POST of a canary |

Each DB payload is self-contained (opens its own JDBC connection with fully-qualified `` DatabaseLink` ``
names, acts, closes). Each FS payload targets a file under its own fresh fixture.

## Result

```
readonly_zero_state_change:      true
all_proven_live_blocked:         true
all_dangerous_blocked_by_guard:  true
bypasses:                        []        (none)
proven_live_count:               16 / 19
```

- **Off (baseline):** 16 of 19 payloads changed state — all 7 DB evasions drove inactive 250 → 0; the 5
  write-primitive payloads each created their `EVIL_*` file; the 3 deletion vectors each removed a research
  file (10 → 9). So the evasions genuinely work when unguarded. (`fs_delete_toexpr` was malformed and inert;
  `proc_runprocess` and `net_url_post` change no synthetic file/DB state, and the network POST is also
  stopped by `$AllowInternet=False`.)
- **ReadOnly (the guard):** every payload returned `[WolframGuard] Blocked …` and **every fixture ended
  pristine** — 1,000 / 250, 10 files, no `EVIL_*`, no `.bak`. Verified independently of the guard's own
  verdict by re-snapshotting all 19 fixtures after the run.

## A real bypass was found and closed on the way

The standalone classifier sweep (before the server run) flagged one payload the guard **allowed**:

- `fs_delete_alias` — `With[{g = DeleteFile}, g["…research_07.txt"]]` → decision **allow**, effects `{}`.
- **Root cause:** membership was tested against call *heads* only. `DeleteFile` here is the *value* bound
  to `g`, not a call head, so the head scan missed it; `g[path]` then deletes the file. This defeats any
  head-only denylist: alias the dangerous function and call the alias. Under `Off` the payload is proven
  live (it deleted a research file).
- **Fix (one idea, one line-class change):** test membership against **every symbol that appears anywhere**
  in the parsed code, not just heads — strictly more conservative. A legitimate read references none of the
  dangerous symbols, so it is unaffected; the `SELECT`-count read still classifies `allow` (verified).
- **After:** `fs_delete_alias` → **block** `{FilesystemWrite}`, fixture pristine.

Recorded in `results/wolframguard-bypass-001/bypass-finding.json`, with the one-line revert to reproduce
the "before". This is the point of the exercise: the battery is what turned an unstated assumption into a
found-and-closed hole.

## Honest scope of the claim

- This says the guard blocks **these 19 techniques** with independently verified zero state change. It is
  **not** a proof of completeness. WolframGuard is a denylist over parsed symbols plus SQL-string
  heuristics; a dangerous primitive whose symbol is **not** in the sets, and that is neither SQL nor a
  dynamic-eval head, would still pass. The battery is designed to be extended — adding a payload that
  slips is exactly how the next gap gets found and closed.
- The dynamic-eval and parse-failure nets (`ToExpression`, `Symbol`, `Get`, unparseable code → high-risk)
  are the backstop for "hide it behind a string": they fire on the *mechanism* of hiding, not the hidden
  content, so keyword-splitting inside `ToExpression` is caught even though the literal scan is not.
- Enforcement is still pre-execution refusal at one point (the evaluator entry). A **permitted** effect
  still runs with full OS rights; WolframGuard is not a sandbox. Confining a permitted effect needs the
  protected-kernel / OS-sandbox work that remains out of scope for this wrapper.

## Reproduce

```powershell
python wolframguard-poc/instrumentation/wolframguard_bypass_tests.py --run-id wolframguard-bypass-new
```

Requires non-administrator Windows, Wolfram 15.0.1 + AgentTools 2.2.0, free loopback port 8765. No model,
no client, no network egress. Then check `results/wolframguard-bypass-new/summary.json` → `verdict`
(`readonly_zero_state_change`, `bypasses`), and re-snapshot the `readonly/payload_*/fixture` dirs: every
one must be 1,000 / 250 with 10 files and no `EVIL_*`.
