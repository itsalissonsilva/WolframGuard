(* Read-only, non-model introspection. Launch with -noinit. This flag is not OS isolation. *)
$AllowInternet = False;
pacletSummary[p_] := <|"name" -> p["Name"], "version" -> p["Version"], "location" -> p["Location"]|>;
Print["WOLFRAMGUARD_DISCOVERY_BEGIN"];
discovery = <|
  "version" -> $Version,
  "version_number" -> $VersionNumber,
  "release_number" -> $ReleaseNumber,
  "system_id" -> $SystemID,
  "operating_system" -> $OperatingSystem,
  "cloud_evaluation" -> $CloudEvaluation,
  "allow_internet" -> $AllowInternet,
  "agenttools" -> (pacletSummary /@ PacletFind["Wolfram/AgentTools"]),
  "alternative_agenttools_identifier" -> (pacletSummary /@ PacletFind["WolframResearch/AgentTools"]),
  "chatbook" -> (pacletSummary /@ PacletFind["Wolfram/Chatbook"]),
  "llmfunctions" -> (pacletSummary /@ PacletFind["Wolfram/LLMFunctions"]),
  "llmconnections" -> (pacletSummary /@ PacletFind["LLMConnections"]),
  "database_link" -> (pacletSummary /@ PacletFind["DatabaseLink"]),
  "interfaces" -> AssociationMap[Length[Names["System`" <> #]] > 0 &, {"LLMSynthesize", "ChatEvaluate", "LLMTool", "LLMConfiguration"}]
|>;
Print[ExportString[discovery, "RawJSON"]];
label = Environment["WOLFRAMGUARD_DISCOVERY_LABEL"];
If[!StringQ[label] || !StringMatchQ[label, RegularExpression["[a-zA-Z0-9-]+"]], label = "manual"];
output = FileNameJoin[{DirectoryName[$InputFileName], "..", "results", "discovery", label <> "-runtime.json"}];
If[FileExistsQ[output], Print["Refusing to overwrite discovery evidence"]; Quit[2]];
Export[output, discovery, "RawJSON"];
Print["WOLFRAMGUARD_DISCOVERY_END"];
Quit[];
