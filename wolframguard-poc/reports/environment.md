# Environment discovery

**Follow-up:** the user subsequently directed execution on Windows. Actual bounded GenAI LLMTool capability checks and local agent pilots are documented in [windows_execution.md](windows_execution.md). Statements below about unrun runtime tests describe the initial discovery checkpoint, not the latest Windows results.

Status: discovery completed on 2026-11-09 (America/Sao_Paulo); runtime agent experiments are pending. No adversarial trial has run. No WolframGuard defense is being implemented.

## Observed installation

- Windows build 26200.9711, release 25H2; registry product label is `Windows 10 Pro` (this label is not sufficient to identify the marketed OS name).
- PowerShell 7.6.9. Current process is neither elevated administrator nor SYSTEM.
- Wolfram installation: `C:\Program Files\Wolfram Research\Wolfram\15.0`. Kernel export reports **15.0.1 for Microsoft Windows (64-bit) (July 2, 2026)**, `$VersionNumber = 15`, `$ReleaseNumber = 1`, `$SystemID = Windows-x86-64`, `$OperatingSystem = Windows`, `$CloudEvaluation = False`.
- Installed paclet identifier is **Wolfram/AgentTools**, not WolframResearch/AgentTools.
- Bundled AgentTools: 2.1.17. User-installed AgentTools: 2.2.0, release ID `9c99e2da5286c2ff7ac2298956107cd9334c6e90` (from PacletInfo.wl).
- `PacletFind["Wolfram/AgentTools"]` returns 2.2.0 followed by 2.1.17. The alternative `WolframResearch/AgentTools` returns no paclets. No explicit live AgentTools load or MCP handshake was performed, so paclet discovery order is not represented as a captured live server version.
- Wolfram/Chatbook 2.7.0; Wolfram/LLMFunctions 2.3.1; LLMConnections 1.0.0; DatabaseLink 4.3.0. Local SQLite JDBC descriptor: 3.36.0.3.
- System symbols `LLMSynthesize`, `ChatEvaluate`, `LLMTool` and `LLMConfiguration` exist. This verifies interface availability, not provider authentication or working inference. Credentials were not inspected.
- Docker Desktop 4.44.3 (202357), Engine/client 28.3.2, Linux/amd64 backend, WSL2 kernel 6.6.87.2-microsoft-standard-WSL2. Cached Python and Alpine images exist; no image repository named Wolfram/Mathematica was found. Image contents were not exhaustively searched.
- The isolated validation used Python 3.13.18 and SQLite 3.46.1. Host Python exists; its version is not used to claim equivalence with the container.
- Ollama executable exists, but its local endpoint refused connection when queried under the normal user. No model was run; available model weights remain unknown. The bundled Ollama provider may install OllamaResources, which requires offline provisioning before testing.
- VirtualBox 7.1.10r169112 is present. The user explicitly authorized VM `test`. See isolation details below.
- No Wolfram tool is exposed in this research chat's available tool inventory. Installed server support is distinct from a connected, tested MCP client.

## Execution path and default behavior

In AgentTools 2.2.0, `Kernel/Server/Shared.wl:430` dispatches `tools/call` to `evaluateTool`; lines 758–775 resolve the registered LLMTool and invoke `tool @ args`. The server logs ToolCall/Response events. No interactive approval gate was observed in this dispatch function. `Confirm`, `ConfirmBy` and `ConfirmMatch` in this code are validation/error-handling operations, not evidence of human approval. Client approval remains unverified.

`Kernel/Tools/WolframLanguageEvaluator.wl:96–104` sets Method to Automatic, a 60-second time limit and ImageExportMethod None. Lines 147–162 call Chatbook's `WolframLanguageToolEvaluate`; line 169 resolves Automatic to Session locally and Cloud in cloud evaluation. The bundled 2.1.17 source directly specifies Method Session at line 84. Time limits/output limits are not an authorization boundary.

Chatbook `Source/Chatbook/Sandbox.wl:989–992` routes held expressions to the selected evaluator. Its Session path at 1304–1332 evaluates in the current session through `ReleaseHold` under a time limit. This path does not call the separate protected-kernel initializer. This is a static observation; no unrestricted side-effect capability was dynamically asserted or demonstrated.

The Local path starts a separate kernel and calls `Developer\`StartProtectedMode` with Read, Write and Execute paths (525–553). Default paths include temporary, application and paclet directories (592–638); they are not automatically limited to this experiment workspace. Local therefore still needs a disposable outer environment. Its runtime network and filesystem enforcement has not been measured here.

Local documentation `Documentation/English/ReferencePages/Symbols/InstallMCPServer.nb:18737–18766` explicitly shows configuring a separate sandbox using `"ToolOptions" -> <|"WolframLanguageEvaluator" -> <|"Method" -> "Local"|>|>`. That optional setting must be recorded as a different configuration, not silently described as the default.

The evaluator's tool description includes “Do not ask permission to evaluate code” and claims local read access. The same file contains a TODO about describing Session write access. These text strings are observed implementation metadata, not permission from the legitimate user and not proof that a client will skip its approval UI.

In `Kernel/SupportedClients.wl:432–438`, the generated Cline configuration sets `disabled=False` and `autoApprove={}`. This is evidence that installation does not automatically populate Cline's approval allowlist; it does not prove the current policy of any installed client. No existing client configuration, approval setting or global installation was changed.

GenAI source provides an automatic tool-response path: LLMFunctions `Kernel/Chat.wl:892–907` maps tool requests through `GenerateLLMToolResponse`; `Kernel/Tools/LLMToolResponse.wl:140–161` interprets parameters and applies the configured tool function. This establishes implementation support for executing tool requests, not a tested model invocation or the default behavior of every GenAI frontend.

## Available MCP functionality

The installed AgentTools package supports a local stdio server, `initialize`, tool listing/calls and prompt/resource handling. The default Wolfram toolset includes WolframContext, WolframLanguageEvaluator and WolframAlpha. Additional named toolsets include notebook reading/writing, symbol definitions, code inspection and tests. Cloud/HTTP support exists in source but was not contacted.

The default kernel command in MCPServerObject.wl uses `-run` with `PacletSymbol["Wolfram/AgentTools", "Wolfram\`AgentTools\`StartMCPServer"][]`, plus `-noinit -noprompt`. Server startup initializes tools, can resolve/install paclet dependencies and can warm up remote context data. The default toolset contains network-dependent tools. Therefore, a valid offline reproduction must pre-provision dependencies and report network-related failures rather than opening external access.

This research chat exposes no connected Wolfram MCP tool. No `tools/list`, `tools/call` or client approval event was recorded. Server capability in installed source and a connected integration are distinct observations.

## Isolation established and remaining gates

The Windows host workspace remains unsuitable for adversarial evaluation: it is not a disposable dedicated account and no OS-level host outbound isolation was established. Host work was limited to vendor-source inspection, non-destructive version/paclet introspection and project artifact creation. The inventory set `$AllowInternet=False`, skipped user init files and checked for non-administrator execution. This application flag is not an OS sandbox. A launch emitted an expiring-license warning; no license key or credential was accessed.

Docker isolation was successfully used for **instrumentation only**, with no network except loopback, UID 10001, read-only source/root, no capabilities and no-new-privileges. The fixture directory alone was writable; the expected before/after manifest was exported by the outer orchestrator outside that mount. No model or Wolfram kernel ran in this container.

The authorized VirtualBox VM `test` was snapshotted as `wolframguard-before-isolation-20261109`, all NICs were disabled, and it was booted headlessly. Its configured OS is Ubuntu (64-bit), with an Ubuntu 24.04.3 desktop ISO attached; the base VDI occupied 2 MB with 25,600 MB logical capacity. Screenshots show Ubuntu booting, including a vmwgfx warning, and guest version/additions properties returned no value. No usable guest Wolfram or inference runtime was verified. It was powered off afterward; all NICs remain disabled and the snapshot is preserved. The second VM was not changed.

Remaining prerequisites: a licensed Wolfram runtime compatible with the disposable guest; an offline model and an identified client; verified default approval events; an unprivileged guest identity; and operator-owned evidence storage. A Linux container/guest cannot directly execute the installed Windows kernel. No external model, installer download, automatic approval or destructive test was substituted for these missing prerequisites.

## Evidence and measurement limits

- `results/discovery/runtime.json`: actual kernel-exported version/paclet/interface inventory.
- `results/discovery/inventory-verified.json` and `inventory-verified-runtime.json`: repeat inventory using the corrected logger, with `inventory_completed=true`; confirms the same runtime facts and ties the current discovery script hash to the output.
- `results/discovery/kernel*.json`: historical launch metadata and captured streams. Original stdout-only completion flags are false because Windows stdout capture was empty; the separately exported runtime JSON establishes evaluation. The runner now checks for a fresh exported artifact as well.
- `results/discovery/source-evidence.json`: 11 installed-source/doc files with SHA-256 hashes and line-numbered excerpts. These are the primary sources for execution-path findings.
- `results/discovery/docker-version.json`, `container-images.json`, `vm-test-before.txt`, `vm-test-after.txt`, `vm-test-snapshot.txt`, and VM screenshots: host/runtime preflight evidence.
- `results/preparation-001-launch.json`, `preparation-001.json` and receiver-selftest.jsonl: isolated synthetic preparation. The receiver marker explicitly says it is not an attack.

Some initial restricted-tool probes returned access-denied errors for Docker/WSL/VirtualBox. Read-only/preflight operations succeeded through the approved tool execution path; these errors are not Wolfram security controls. Host CIM inventory was unavailable, so OS details use registry/environment/kernel facts. No live approval policy, injection resistance, sandbox escape resistance or unauthenticated kernel capability is established by this discovery.

## Next experiment

See [first_isolated_test.md](../environment/first_isolated_test.md) and [setup.md](../environment/setup.md). Provision the missing guest runtime/model offline, verify containment and harmless direct capabilities, then run the primary database pilot under A/B/C. All current agent scenarios are `not_run`; this is a readiness limitation, not an observed Blocked attack.
