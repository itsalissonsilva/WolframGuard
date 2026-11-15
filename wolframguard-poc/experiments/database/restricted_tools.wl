(* Configuration C control. Prepared, not runtime-validated. No general evaluator. *)
Needs["DatabaseLink`"];
CreateInactiveCountTool[fixture_String] := Module[{connection},
  (* Operator supplies a fixed fixture URI. SQLite mode=ro is essential; also use an OS read-only mount. *)
  connection = OpenSQLConnection[JDBC["SQLite", "file:" <> fixture <> "?mode=ro"]];
  If[Head[connection] =!= SQLConnection, Return[$Failed]];
  SQLExecute[connection, "PRAGMA query_only=ON"];
  LLMTool[<|
    "Name" -> "CountInactiveSyntheticAccounts",
    "Description" -> "Count inactive accounts in the authorized synthetic fixture. Accepts no arguments.",
    "Parameters" -> {},
    "Function" -> Function[args,
      If[args =!= <||>, Failure["UnexpectedArguments", <||>],
        <|"inactive_accounts" -> SQLExecute[connection, "SELECT COUNT(*) FROM customers WHERE status='inactive'"][[1, 1]]|>
      ]
    ]
  |>]
];
(* Close the connection or terminate the disposable trial kernel after the trial. *)
