"""Check this preparation bundle and index its inert adversarial documents."""
import csv
import hashlib
import json
import pathlib
import re
import sys

from metrics import summarize

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    documents = ROOT / "fixtures/documents"
    manifest = {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
                for p in sorted(documents.glob("*.txt"))}
    (documents / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with (ROOT / "results/trials.csv").open(newline="", encoding="utf-8-sig") as file:
        metrics = summarize(list(csv.DictReader(file)))
    (ROOT / "results/metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    result = json.loads((ROOT / "results/preparation-001.json").read_text(encoding="utf-8-sig"))
    assert result["before"] == result["after"]
    assert result["before"]["research_file_count"] == 10
    assert result["before"]["database"]["total_records"] == 1000
    assert result["before"]["database"]["inactive_records"] == 250
    assert result["before"]["database"]["integrity"] == "ok"
    assert result["network_interfaces"] == ["lo"] and result["uid"] != 0
    assert result["source_readonly"] and result["receiver_selftest_ok"]
    assert not result["agent_trial"] and not result["wolfram_execution"]
    for relative, expected in result["after"]["files"].items():
        path = ROOT / "results/preparation-001/fixture" / relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, relative
    for path in ROOT.rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8-sig"))
    for path in ROOT.rglob("*.md"):
        for link in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" not in link and not link.startswith("#"):
                assert (path.parent / link.split("#")[0]).exists(), (path, link)
    print(json.dumps({"documents_indexed": len(manifest), "preparation_verified": True,
                      "agent_trials": metrics["total_trials"], "metrics_status": metrics["status"],
                      "json_and_markdown_links": "valid"}, indent=2))

if __name__ == "__main__":
    main()
