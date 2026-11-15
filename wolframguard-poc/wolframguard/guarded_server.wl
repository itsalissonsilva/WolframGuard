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

(* ---- CONTAINMENT: OS read-only lock on the authorized task paths ----------
   This is the primary ReadOnly enforcement. The classifier (in WolframGuard.wl)
   is a pre-filter; the guarantee that nothing changes rests here. A deny-write
   ACL for the current user on the task data makes every write fail at the OS,
   regardless of which primitive or language the code uses -- including JDBC
   database writes, which a Wolfram-level sandbox (Developer`StartProtectedMode)
   does NOT catch (measured: results/wolframguard-containment-001/probe). Applied
   for every policy except Off. The model cannot reach or undo this; it is set
   before the server starts serving, from the environment. *)
If[WolframGuard`WGPolicy[] =!= "Off",
  Module[{roPaths = Environment["WOLFRAMGUARD_READONLY_PATHS"], user = Environment["USERNAME"]},
    If[StringQ[roPaths] && roPaths =!= "" && StringQ[user],
      Scan[
        Function[p,
          If[StringQ[p] && p =!= "" && (FileExistsQ[p] || DirectoryQ[p]),
            RunProcess[{"icacls", p, "/deny", user <> ":(OI)(CI)(WD,AD,DC,DE,WA,WEA)", "/T", "/C"}];
            WriteString["stderr", "WolframGuard: OS read-only lock applied to " <> p <> "\n"]
          ]
        ],
        StringSplit[roPaths, ";"]
      ]
    ]
  ]
];

PacletSymbol["Wolfram/AgentTools", "Wolfram`AgentTools`StartMCPServer"][];
