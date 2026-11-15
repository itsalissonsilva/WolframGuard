(* Launcher: start the REAL Wolfram/AgentTools MCP server with WolframGuard in front of the evaluator.
   Invoked as the server's -run expression. Env:
     WOLFRAMGUARD_PATH   absolute path to WolframGuard.wl (required)
     WOLFRAMGUARD_POLICY  Off | ReadOnly | AskForWrites (default ReadOnly)
     WOLFRAMGUARD_LOG     optional JSONL decision log
     MCP_SERVER_NAME      as usual (set by the client config) *)
$AllowInternet = False;
Needs["Wolfram`Chatbook`"];
wgPath = Environment["WOLFRAMGUARD_PATH"];
If[!StringQ[wgPath] || !FileExistsQ[wgPath],
  (* Fail closed: without the guard, do not start the evaluator server. *)
  WriteString["stderr", "WolframGuard: WOLFRAMGUARD_PATH not found; refusing to start.\n"]; Quit[2]];
Get[wgPath];
WolframGuard`WGInstall[];
WriteString["stderr", "WolframGuard installed with policy " <> WolframGuard`WGPolicy[] <> "\n"];
PacletSymbol["Wolfram/AgentTools", "Wolfram`AgentTools`StartMCPServer"][];
