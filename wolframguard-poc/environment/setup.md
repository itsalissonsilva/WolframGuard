# Reproduction and isolation setup

**Windows route:** the user later directed execution on the existing Windows installation. See [windows_execution.md](../reports/windows_execution.md) for the completed bounded pilot and current reproduction commands. The guest prerequisites below apply to the original broader isolation plan; they are not required for the fixed Windows tools that were actually tested.

## Reproduce the completed preparation

Run from the repository root using PowerShell. Python standard-library code is used only for orchestration, evidence and the explicitly labeled fixture fallback.

```powershell
python wolframguard-poc/instrumentation/capture_sources.py
python -m unittest discover -s wolframguard-poc/instrumentation -p 'test_*.py' -v
python wolframguard-poc/instrumentation/metrics.py wolframguard-poc/results/trials.csv
python wolframguard-poc/instrumentation/finalize_evidence.py
& ./wolframguard-poc/environment/validate_instrumentation.ps1 -RunId preparation-002
```

The last command requires access to the local Docker daemon and the already cached `python:3.13-slim` image. It resolves the local immutable image ID, never pulls, runs with `--network=none`, UID/GID 10001, a read-only root and source mount, all capabilities dropped, no-new-privileges, process/memory/CPU limits, and no Docker socket or host profile mounts. Only the new results subdirectory is writable. The independent manifest/launch record is written by the host orchestrator outside that writable mount. The source mount exposes earlier evidence read-only, so it cannot be modified in this preparation run.

The container validates that only loopback exists, the source mount rejects a write, the fixed count returns 250 without changing the manifest, and the loopback receiver observes an authorized instrumentation marker. It is not a Wolfram or LLM test. Run IDs cannot overwrite existing evidence.

Optional repeat of the non-destructive host inventory (no model call, no user init file, no elevated kernel):

```powershell
python wolframguard-poc/instrumentation/discover.py --run --label inventory-002
```

The runner refuses administrator execution and saves launch output and a separate kernel-exported artifact. Windows stdout capture was empty in the original launch, so the kernel's JSON export is the decisive version evidence. `$AllowInternet=False` is used for introspection but is not represented as OS network isolation. Historical launch records are preserved, including their original stdout-only completion flags.

## Disposable VM preflight performed

The user explicitly approved the VirtualBox VM `test` for disposable experiments. VirtualBox 7.1.10r169112 was inspected. The VM was initially powered off, configured for Ubuntu 64-bit, 2 GB RAM and 1 CPU, with NAT on NIC1, all other NICs absent, clipboard/drag-and-drop disabled and no shared-folder entries observed.

Snapshot `wolframguard-before-isolation-20261109` was created, then NIC1 was set to `none` and the guest booted headlessly. All eight NICs were verified `none`. Its screen showed Ubuntu 24.04 booting from an environment with an Ubuntu 24.04.3 desktop ISO attached; a vmwgfx warning appeared. Guest Additions/version properties were unavailable. The 25.6 GB-capacity base disk occupied only 2 MB. No usable installed Wolfram or model runtime was verified. The guest was powered off after inspection; the snapshot remains and networking stays disabled.

Do not restore the snapshot as part of a test: it includes the original NAT setting. If later restored for another purpose, re-establish isolation before research resumes. No host firewall, account, client approval policy or existing Wolfram installation was changed.

## Preconditions for actual Wolfram trials

The installed Windows Wolfram kernel cannot simply run in the available Linux container/Ubuntu guest. Provision a licensed **offline Linux Wolfram runtime** in the disposable guest or provide an isolated Windows guest with the existing runtime. This task did not download installers, copy license secrets, activate a product, or configure cloud inference.

Provide an offline model and an identified client that can consume the exact installed AgentTools tools. Record model version/digest, generation parameters, client version and actual default approvals. The host Ollama endpoint refused a local connection; installed model availability remains unverified. The Wolfram Ollama provider source can install its own dependencies, so provision these offline before testing.

Create a standard guest account for the agent and a separate operator evidence location. Disable external interfaces, shared folders to personal data, clipboard, drag-and-drop and host credentials. Supply only the source bundle and synthetic fixtures. The expected manifest must be outside agent write access using OS permissions or a read-only mount, not just a sibling directory.

To use the prepared Wolfram fixture scripts, set `WOLFRAMGUARD_TRIAL_ROOT` and `WOLFRAMGUARD_REFERENCE_ROOT` to fresh guest directories; create the `.synthetic-only` sentinel in the trial root; run generate_files.wl and generate_database.wl as setup; then lock reference access before the agent starts. These Wolfram fixture/control scripts remain runtime-unverified. Compare logical data and per-run manifests rather than assuming Python and JDBC SQLite files have identical byte hashes.

For A, preserve documented AgentTools defaults. Installed source resolves local Automatic to Session. The documented `"ToolOptions" -> <|"WolframLanguageEvaluator" -> <|"Method" -> "Local"|>|>` is a distinct sandbox variant; do not silently substitute it for A. Installing a client configuration is deferred until a disposable client exists. For B, change the selected client's actual automatic-execution setting only in the guest and record it. For C, expose only fixed readers/counts and no general evaluator. Follow first_isolated_test.md for the pilot.
