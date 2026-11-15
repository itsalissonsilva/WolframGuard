"""Probe: what does Developer`StartProtectedMode actually contain on this machine?
Also: can untrusted code escape via EndProtectedMode, and does an OS read-only lock contain JDBC?
We measure STATE independently (Python sqlite + os) rather than trusting the kernel's own say-so.
"""
import json, os, pathlib, subprocess, sqlite3, stat, sys

WOLFRAM = r"C:\Program Files\Wolfram Research\Wolfram\15.0\wolfram.exe"
BASE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "probe_run"
BASE.mkdir(parents=True, exist_ok=True)

def build_db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, status TEXT)")
    con.executemany("INSERT INTO customers VALUES (?,?,?)",
                    [(n, f"c{n}", "inactive" if n % 4 == 0 else "active") for n in range(1, 1001)])
    con.commit(); con.close()

def inactive(path):
    con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    n = con.execute("SELECT COUNT(*) FROM customers WHERE status='inactive'").fetchone()[0]
    con.close(); return n

def wlstr(p):  # WL string literal of a path
    return json.dumps(str(p))

# --- scenario A: in-session StartProtectedMode (no OS lock) -------------------
fixture = BASE / "A_protected"; fixture.mkdir(exist_ok=True)
research = fixture / "research"; research.mkdir(exist_ok=True)
scratch = fixture / "scratch"; scratch.mkdir(exist_ok=True)
for name in ("del_wl.txt", "del_after_end.txt", "rename_me.txt"):
    (research / name).write_text("synthetic", encoding="utf-8")
dbA = fixture / "db.sqlite"; build_db(dbA)
dbA_inactive_before = inactive(dbA)

wl = f"""
$AllowInternet = False;
Needs["DatabaseLink`"];
(* warm the JVM + open a live connection BEFORE protection, worst case for the sandbox *)
cWarm = DatabaseLink`OpenSQLConnection[DatabaseLink`JDBC["SQLite", {wlstr(dbA)}]];
Print["warm_conn_head=", Head[cWarm]];

Developer`StartProtectedMode[
  "Read"    -> {{ {wlstr(fixture)}, {wlstr(scratch)} }},
  "Write"   -> {{ {wlstr(scratch)} }},
  "Execute" -> {{ }},
  "ResolveAllowedPaths" -> False
];

rDel = Quiet @ Check[DeleteFile[{wlstr(research / "del_wl.txt")}], "FAILED"];
Print["A_wl_deletefile_ret=", ToString[rDel], " still_exists=", FileExistsQ[{wlstr(research / "del_wl.txt")}]];

rOpen = Quiet @ Check[Module[{{s=OpenWrite[{wlstr(research / "evil_openwrite.txt")}]}}, WriteString[s,"x"]; Close[s]], "FAILED"];
Print["A_wl_openwrite_ret=", ToString[rOpen], " created=", FileExistsQ[{wlstr(research / "evil_openwrite.txt")}]];

rRun = Quiet @ Check[RunProcess[{{"cmd","/c","echo wolframguard"}}], "FAILED"];
Print["A_runprocess_ret=", ToString[rRun]];

(* JDBC DELETE via the already-open warm connection *)
rJ = Quiet @ Check[DatabaseLink`SQLExecute[cWarm, "DELETE FROM customers WHERE status='inactive'"], "FAILED"];
Print["A_jdbc_delete_ret=", ToString[rJ]];

(* escape attempt: end protected mode, then delete *)
rEnd = Quiet @ Check[Developer`EndProtectedMode[], "END-FAILED"];
Print["A_endprotected_ret=", ToString[rEnd]];
rDel2 = Quiet @ Check[DeleteFile[{wlstr(research / "del_after_end.txt")}], "FAILED"];
Print["A_delete_after_end_still_exists=", FileExistsQ[{wlstr(research / "del_after_end.txt")}]];

DatabaseLink`CloseSQLConnection[cWarm];
Print["A_DONE"];
Quit[];
"""
(BASE / "probeA.wl").write_text(wl, encoding="utf-8")

# --- scenario B: OS read-only lock (deny-write ACL) + JDBC, no protected mode -
fixtureB = BASE / "B_osreadonly"; fixtureB.mkdir(exist_ok=True)
dbB = fixtureB / "db.sqlite"; build_db(dbB)
dbB_inactive_before = inactive(dbB)
fileB = fixtureB / "del_me.txt"; fileB.write_text("synthetic", encoding="utf-8")
user = os.environ.get("USERNAME", "")
# deny write/append/delete (incl. child) on the whole fixtureB dir, inherited to files
deny = subprocess.run(["icacls", str(fixtureB), "/deny", f"{user}:(OI)(CI)(WD,AD,DC,DE,WA,WEA)"],
                      capture_output=True, text=True)
wlB = f"""
$AllowInternet = False;
Needs["DatabaseLink`"];
cB = DatabaseLink`OpenSQLConnection[DatabaseLink`JDBC["SQLite", {wlstr(dbB)}]];
Print["B_conn_head=", Head[cB]];
rJB = Quiet @ Check[DatabaseLink`SQLExecute[cB, "DELETE FROM customers WHERE status='inactive'"], "FAILED"];
Print["B_jdbc_delete_ret=", ToString[rJB]];
rDB = Quiet @ Check[DeleteFile[{wlstr(fileB)}], "FAILED"];
Print["B_wl_delete_ret=", ToString[rDB], " still_exists=", FileExistsQ[{wlstr(fileB)}]];
Quiet @ Check[DatabaseLink`CloseSQLConnection[cB], Null];
Print["B_DONE"];
Quit[];
"""
(BASE / "probeB.wl").write_text(wlB, encoding="utf-8")

def run_wl(script):
    p = subprocess.run([WOLFRAM, "-noinit", "-noprompt", "-script", str(script)],
                       capture_output=True, text=True, timeout=240)
    return p.stdout, p.stderr

outA, errA = run_wl(BASE / "probeA.wl")
# measure A state independently
A_state = {
    "db_inactive_before": dbA_inactive_before,
    "db_inactive_after": inactive(dbA),
    "del_wl_still_exists": (research / "del_wl.txt").exists(),
    "evil_openwrite_created": (research / "evil_openwrite.txt").exists(),
    "del_after_end_still_exists": (research / "del_after_end.txt").exists(),
}

outB, errB = run_wl(BASE / "probeB.wl")
# release the deny ACL so we (and cleanup) can read/remove afterwards
subprocess.run(["icacls", str(fixtureB), "/remove:d", user], capture_output=True, text=True)
B_state = {
    "icacls_deny_rc": deny.returncode, "icacls_deny_out": (deny.stdout + deny.stderr).strip()[:200],
    "db_inactive_before": dbB_inactive_before,
    "db_inactive_after": inactive(dbB),
    "del_me_still_exists": fileB.exists(),
}

print("=== SCENARIO A: in-session StartProtectedMode ===")
print(outA)
if errA.strip(): print("[stderrA]", errA[:1000])
print("A measured state:", json.dumps(A_state, indent=2))
print("=== SCENARIO B: OS deny-write ACL + JDBC ===")
print(outB)
if errB.strip(): print("[stderrB]", errB[:1000])
print("B measured state:", json.dumps(B_state, indent=2))
