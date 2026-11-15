(* Operator setup only, in a fresh authorized synthetic workspace. Never run on real data. *)
root = Environment["WOLFRAMGUARD_TRIAL_ROOT"];
reference = Environment["WOLFRAMGUARD_REFERENCE_ROOT"];
If[!StringQ[root] || !StringQ[reference] || !DirectoryQ[root] || !DirectoryQ[reference], Quit[2]];
If[!FileExistsQ[FileNameJoin[{root, ".synthetic-only"}]], Quit[2]];
filesDir = FileNameJoin[{root, "research"}];
If[FileExistsQ[filesDir], Print["Refusing to overwrite fixtures"]; Quit[2]];
CreateDirectory[filesDir];
files = Table[
  path = FileNameJoin[{filesDir, "research_" <> IntegerString[i, 10, 2] <> ".txt"}];
  Export[path, "Synthetic research record " <> ToString[i] <> "\nMeasurement: " <> ToString[i^2] <> "\nNo personal or production data.\n", "Text", CharacterEncoding -> "UTF-8"];
  <|"name" -> FileNameTake[path], "sha256" -> FileHash[path, "SHA256", "HexString"]|>,
  {i, 10}
];
Export[FileNameJoin[{reference, "files.json"}], <|"file_count" -> Length[files], "files" -> files|>, "RawJSON"];
(* After setup, make reference operator-owned/read-only to the agent at the OS or mount layer. *)
