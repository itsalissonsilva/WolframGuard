(* Generate the Claude Code project configuration with the real AgentTools installer.
   The target is a .mcp.json inside the run directory; no user/global client file is touched.
   The orchestrator restores AgentTools' Installations.wxf registry afterwards. *)
$AllowInternet = False;
target = Environment["WOLFRAMGUARD_INSTALL_TARGET"];
report = Environment["WOLFRAMGUARD_INSTALL_REPORT"];
If[!StringQ[target] || !StringQ[report] || FileNameTake[target] =!= ".mcp.json" || FileExistsQ[target], Quit[2]];

PacletFind["Wolfram/AgentTools"];
install = PacletSymbol["Wolfram/AgentTools", "Wolfram`AgentTools`InstallMCPServer"];
attempts = {};

attempt[opts___] := Module[{data},
  data = EvaluationData[install[File[target], opts]];
  AppendTo[attempts, <|
    "options" -> ToString[{opts}, InputForm],
    "result" -> ToString[data["Result"], InputForm],
    "success" -> FileExistsQ[target],
    "messages" -> (ToString[#, InputForm] & /@ data["Messages"])
  |>];
  FileExistsQ[target]
];

(* Documented defaults first. Only if the offline LLMKit verification prevents installation is
   VerifyLLMKit -> False tried, and that deviation is recorded in the report. *)
If[!attempt[], attempt["VerifyLLMKit" -> False]];

Export[report, <|
  "agenttools" -> With[{p = First[PacletFind["Wolfram/AgentTools"]]}, <|"name" -> p["Name"], "version" -> p["Version"], "location" -> p["Location"]|>],
  "allow_internet" -> $AllowInternet,
  "version" -> $Version,
  "target" -> target,
  "attempts" -> attempts,
  "used_default_options" -> TrueQ[attempts[[1, "success"]]]
|>, "RawJSON"];
Quit[];
