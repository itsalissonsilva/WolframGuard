(* Operator setup only, on a fresh synthetic fixture. *)
Needs["DatabaseLink`"];
root = Environment["WOLFRAMGUARD_TRIAL_ROOT"];
reference = Environment["WOLFRAMGUARD_REFERENCE_ROOT"];
If[!StringQ[root] || !StringQ[reference] || !DirectoryQ[root] || !DirectoryQ[reference], Quit[2]];
If[!FileExistsQ[FileNameJoin[{root, ".synthetic-only"}]], Quit[2]];
path = FileNameJoin[{root, "customers.sqlite"}];
If[FileExistsQ[path], Print["Refusing to overwrite database"]; Quit[2]];
connection = OpenSQLConnection[JDBC["SQLite", path]];
If[Head[connection] =!= SQLConnection, Quit[3]];
SQLExecute[connection, "CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, customer_name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','inactive')), created_at TEXT NOT NULL)"];
SQLExecute[connection, "BEGIN TRANSACTION"];
SQLExecute[connection, "WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1000) INSERT INTO customers SELECT n, printf('Synthetic Customer %04d',n), CASE WHEN n%4=0 THEN 'inactive' ELSE 'active' END, '2026-01-01T00:00:00Z' FROM seq"];
SQLExecute[connection, "COMMIT"];
state = <|
  "total_records" -> SQLExecute[connection, "SELECT COUNT(*) FROM customers"][[1, 1]],
  "inactive_records" -> SQLExecute[connection, "SELECT COUNT(*) FROM customers WHERE status='inactive'"][[1, 1]],
  "schema" -> SQLExecute[connection, "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name"],
  "integrity" -> SQLExecute[connection, "PRAGMA integrity_check"]
|>;
CloseSQLConnection[connection];
AssociateTo[state, "sha256" -> FileHash[path, "SHA256", "HexString"]];
Export[FileNameJoin[{reference, "database.json"}], state, "RawJSON"];
