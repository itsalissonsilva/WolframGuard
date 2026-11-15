(* WolframGuard (minimal, hackathon). A pre-execution effect gate for the Wolfram/AgentTools
   WolframLanguageEvaluator. It parses model-supplied code WITHOUT evaluating it, classifies the
   effects it would have, and enforces a policy independent of the MCP client's approval UI.

   This is NOT the AgentTools paclet. It wraps Wolfram`Chatbook`WolframLanguageToolEvaluate, the
   single entry point the evaluator calls (WolframLanguageEvaluator.wl:150), so every evaluation,
   whether or not the client approved the tool, passes through the gate first.

   Policies (env WOLFRAMGUARD_POLICY):
     "Off"         - gate installed but allows everything (baseline; still logs).
     "ReadOnly"    - block any state-changing or outbound effect; allow pure reads/compute. (default)
     "AskForWrites"- allow reads; dangerous effects are refused with an approval-required message
                     (headless has no human approver, so this blocks and labels the decision).

   The model can never widen the policy; it is read once from the environment at install time. *)

BeginPackage["WolframGuard`"];

WGClassify::usage      = "WGClassify[code] returns an association describing the effects of code.";
WGInstall::usage       = "WGInstall[] wraps the evaluator entry point with the gate.";
WGPolicy::usage        = "WGPolicy[] is the active policy string.";

Begin["`Private`"];

(* ---- policy + logging ---------------------------------------------------- *)
$policy := $policy = Module[{p = Environment["WOLFRAMGUARD_POLICY"]},
  If[MemberQ[{"Off", "ReadOnly", "AskForWrites"}, p], p, "ReadOnly"]];
WGPolicy[] := $policy;

$logFile := Environment["WOLFRAMGUARD_LOG"];
logDecision[rec_] := Module[{f = $logFile},
  If[StringQ[f],
    Quiet@WithCleanup[
      Null,
      Export[f, rec, "ExpressibleJSON", "Compact" -> True] // (BinaryWrite[f, ""] &),
      Null
    ]
  ]
];
(* Append one JSON line (Export truncates, so append manually). *)
appendLog[rec_] := Module[{f = $logFile, line},
  If[StringQ[f],
    line = Quiet@Developer`WriteRawJSONString[rec, "Compact" -> True];
    If[StringQ[line],
      Quiet@Module[{s = OpenAppend[f, CharacterEncoding -> "UTF-8"]},
        If[Head[s] === OutputStream, WriteString[s, line <> "\n"]; Close[s]]
      ]
    ]
  ]
];

(* ---- effect categories --------------------------------------------------- *)
(* Head names (context stripped) that produce each effect. Minimal but covers the gap tests. *)
$filesystemWrite = {"DeleteFile", "DeleteDirectory", "DeleteObject", "RenameFile", "RenameDirectory",
  "CopyFile", "CopyDirectory", "CreateFile", "CreateDirectory", "Put", "PutAppend", "Save",
  "WriteString", "Write", "BinaryWrite", "Export", "SetFileDate", "SetPermissions"};
$process = {"Run", "RunProcess", "StartProcess", "ProcessConnection", "SystemShellExecute"};
$network = {"URLRead", "URLExecute", "URLDownload", "URLDownloadSubmit", "URLSubmit", "URLFetch",
  "HTTPRequest", "HTTPResponse", "SendMail", "SocketConnect", "SocketOpen", "ServiceConnect",
  "ServiceExecute", "CloudDeploy", "CloudPut", "CloudPublish", "ChannelSend", "ExternalEvaluate"};
(* Only primitives that evaluate attacker-constructed CODE. Deliberately excludes Needs/Import/Read/
   GetEnvironment, which are needed by legitimate read tasks (e.g. Needs["DatabaseLink`"]) and read data,
   not code. Get is included because it loads and runs an arbitrary file. *)
$dynamic = {"ToExpression", "MakeExpression", "ToHeldExpression", "Symbol", "Get", "Interpreter",
  "SemanticInterpretation"};
$java = {"JavaNew", "LoadJavaClass", "InstallJava", "JavaObject", "JavaBlock"};
$installish = {"PacletInstall", "PacletInstallSubmit", "Install", "SetEnvironment",
  "CreateScheduledTask", "LocalSubmit", "SystemInstall", "ResourceFunction", "ResourceSubmit"};
$sqlHeads = {"SQLExecute", "SQLDelete", "SQLUpdate", "SQLInsert", "SQLDropTable", "SQLCreateTable",
  "SQLConnectionPool"};
$sqlMutationRE = RegularExpression["(?i)\\b(DELETE|UPDATE|DROP|INSERT|ALTER|REPLACE|TRUNCATE|CREATE|MERGE|GRANT|ATTACH)\\b"];

(* ---- classification ------------------------------------------------------ *)
WGClassify[code_String] := Module[
  {held, heads, names, strings, effects = {}, sqlPresent, sqlMut, risk, dangerous, decision, reason},

  held = Quiet@ToExpression[code, StandardForm, HoldComplete];
  If[Head[held] =!= HoldComplete,
    Return[<|"effects" -> {"ParseFailure"}, "symbols" -> {}, "risk" -> "High",
      "dangerous" -> True, "decision" -> If[$policy === "Off", "allow", "block"],
      "reason" -> "Code could not be parsed for analysis; treated as high-risk."|>]
  ];

  heads = DeleteDuplicates@Cases[held, h_Symbol[___] :> SymbolName[Unevaluated[h]], Infinity, Heads -> True];
  names = DeleteDuplicates@Cases[held, s_Symbol :> SymbolName[Unevaluated[s]], Infinity, Heads -> True];
  strings = Cases[held, s_String :> s, Infinity];

  If[IntersectingQ[heads, $filesystemWrite], AppendTo[effects, "FilesystemWrite"]];
  If[IntersectingQ[heads, $process],         AppendTo[effects, "Process"]];
  If[IntersectingQ[heads, $network],         AppendTo[effects, "Network"]];
  If[IntersectingQ[names, $java],            AppendTo[effects, "Java"]];
  If[IntersectingQ[heads, $installish],      AppendTo[effects, "InstallOrEnv"]];
  If[IntersectingQ[names, $dynamic],         AppendTo[effects, "DynamicEval"]];

  sqlPresent = IntersectingQ[heads, $sqlHeads];
  sqlMut = AnyTrue[strings, StringContainsQ[#, $sqlMutationRE] &];
  Which[
    sqlPresent && sqlMut, AppendTo[effects, "DatabaseMutation"],
    sqlPresent && AnyTrue[strings, StringContainsQ[#, RegularExpression["(?i)\\bSELECT\\b"]] &],
      AppendTo[effects, "DatabaseRead"],
    sqlPresent, AppendTo[effects, "DatabaseAccessUnknown"]
  ];
  (* A mutation keyword in a literal with no SQL head is still suspicious (e.g. prose SQL). *)
  If[!sqlPresent && sqlMut, AppendTo[effects, "DatabaseMutation"]];

  dangerous = IntersectingQ[effects,
    {"FilesystemWrite", "Process", "Network", "Java", "InstallOrEnv", "DynamicEval",
     "DatabaseMutation", "DatabaseAccessUnknown", "ParseFailure"}];

  risk = Which[dangerous, "High", effects =!= {}, "Low", True, "None"];

  decision = Which[
    $policy === "Off", "allow",
    !dangerous, "allow",
    $policy === "AskForWrites", "needs-approval",
    True, "block"
  ];

  reason = Which[
    decision === "allow" && !dangerous, "No state-changing or outbound effect detected.",
    decision === "allow", "Policy Off: gate is passive.",
    decision === "needs-approval",
      "Effect(s) " <> StringRiffle[effects, ", "] <> " require explicit human approval.",
    True, "Blocked under " <> $policy <> " policy: effect(s) " <> StringRiffle[effects, ", "] <> "."
  ];

  <|"effects" -> effects, "symbols" -> heads, "risk" -> risk,
    "dangerous" -> dangerous, "decision" -> decision, "reason" -> reason|>
];

(* ---- install (wrap the evaluator entry point) ---------------------------- *)
$installed = False;

WGInstall[] := (
  Needs["Wolfram`Chatbook`"];
  If[TrueQ[$installed], Return[$policy]];

  (* Preserve the original definition under a private symbol. *)
  DownValues[wgOriginalEvaluate] =
    DownValues[Wolfram`Chatbook`WolframLanguageToolEvaluate] /.
      HoldPattern[Wolfram`Chatbook`WolframLanguageToolEvaluate] -> wgOriginalEvaluate;

  Unprotect[Wolfram`Chatbook`WolframLanguageToolEvaluate];
  ClearAll[Wolfram`Chatbook`WolframLanguageToolEvaluate];

  Wolfram`Chatbook`WolframLanguageToolEvaluate[code_String, rest___] :=
    Module[{verdict = WGClassify[code]},
      appendLog[<|
        "timestamp" -> DateString["ISODateTime"], "policy" -> $policy,
        "code" -> code, "effects" -> verdict["effects"], "risk" -> verdict["risk"],
        "decision" -> verdict["decision"]|>];
      Switch[verdict["decision"],
        "allow", wgOriginalEvaluate[code, rest],
        "needs-approval",
          "[WolframGuard] This evaluation needs explicit human approval and was not run.\n" <>
          "Policy: " <> $policy <> "\nDetected effects: " <> StringRiffle[verdict["effects"], ", "] <>
          "\nThe authorized task did not request these effects. No code was evaluated.",
        _,
          "[WolframGuard] Blocked by WolframGuard (" <> $policy <> " policy). No code was evaluated.\n" <>
          "Detected effects: " <> StringRiffle[verdict["effects"], ", "] <> "\n" <> verdict["reason"] <>
          "\nIf this effect is genuinely required, the user must relaunch with a policy that permits it."
      ]
    ];
  (* keep other arities (e.g. held-code) delegating to the original *)
  Wolfram`Chatbook`WolframLanguageToolEvaluate[other___] := wgOriginalEvaluate[other];

  $installed = True;
  $policy
);

End[];
EndPackage[];
