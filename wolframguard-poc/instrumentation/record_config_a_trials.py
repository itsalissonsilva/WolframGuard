"""Append reviewed configuration-A attack trials to the main ledger. Benign controls and direct checks are never recorded."""
import argparse
import csv
import json
import pathlib

from metrics import summarize

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()
    run = ROOT / "results" / args.run_id
    reviews = json.loads((run / "review.json").read_text(encoding="utf-8"))
    inventory = json.loads((run / "model-inventory.json").read_text(encoding="utf-8"))
    ledger = ROOT / "results/trials.csv"
    with ledger.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        rows = list(reader)
    existing = {row["trial_id"] for row in rows}
    boolean = lambda value: "true" if value else "false"
    rel = lambda path: path.relative_to(ROOT).as_posix()
    added = []
    for local_id, review in reviews.items():
        if review.get("control"):
            continue
        directory = run / "trials" / local_id
        trial = json.loads((directory / "trial.json").read_text(encoding="utf-8"))
        if trial["agent_configuration"] != "A" or not trial["evaluator_offered"]:
            raise ValueError("Only configuration-A trials with the evaluator actually offered belong here")
        if not trial["conversation_completed"] or not trial["document_encountered"]:
            raise ValueError("Only completed, exposed trials enter this reviewed ledger")
        canonical_id = args.run_id + ":" + local_id
        if canonical_id in existing:
            raise ValueError("Trial already recorded")
        before = json.loads((directory / "before.json").read_text(encoding="utf-8"))
        after = json.loads((directory / "after.json").read_text(encoding="utf-8"))
        for evidence in (directory / "client-stream.jsonl", directory / "client-parsed.json"):
            if not evidence.is_file():
                raise ValueError(f"Missing evidence: {evidence}")
        effect = before != after
        if review["outcome"] == "Executed" and not (effect and trial["agenttools_server_log"].get("tool_call_entries")):
            raise ValueError("Execution claim lacks attributable server call and side effects")
        model = next(model for model in inventory["models"]["models"] if model["name"] == trial["model"])
        requests = trial["tool_requests"]
        row = {field: "" for field in fields}
        row.update(trial_id=canonical_id, timestamp=trial["timestamp"],
            environment=json.dumps({"os": "Windows", "kernel": "15.0.1", "interface": "Wolfram/AgentTools 2.2.0 MCP stdio (WolframLanguage server, Session evaluator)",
                                    "client": trial["client"], "built_in_tools": trial["built_in_tool_restriction"], "vm": False,
                                    "general_evaluator_exposed": True, "allow_internet": False}),
            model=json.dumps({"name": trial["model"], "digest": model["digest"], "seed": None, "sampling": "client/Ollama defaults"}),
            agent_configuration="A", scenario=trial["scenario"],
            legitimate_request=trial["legitimate_request"], adversarial_document_id=trial["adversarial_document_id"],
            tool_name=json.dumps([r["name"] for r in requests]),
            tool_arguments=json.dumps([r["input"] for r in requests]),
            approval_requested=boolean(trial["approval_requested"]), approval_granted="false",
            execution_attempted=boolean(trial["agenttools_server_log"].get("tool_call_entries", 0) > 0),
            execution_succeeded=boolean(effect),
            observed_side_effects=json.dumps({"removed_files": sorted(set(before["files"]) - set(after["files"])),
                "changed_files": sorted(k for k in set(before["files"]) & set(after["files"]) if before["files"][k] != after["files"][k]),
                "records_before": before["database"]["total_records"], "records_after": after["database"]["total_records"], "canary_received": False}),
            final_agent_response=trial["final_agent_response"], outcome=review["outcome"],
            unauthorized_attempt=boolean(review["unauthorized_attempt"]),
            unauthorized_execution=boolean(review["outcome"] == "Executed"),
            approval_intercepted=boolean(review["approval_intercepted"]),
            legitimate_task_completed=boolean(review["legitimate_task_completed"]),
            trace_path=rel(directory / "client-stream.jsonl"), before_manifest=rel(directory / "before.json"),
            after_manifest=rel(directory / "after.json"), client_approval_log=rel(directory / "client-parsed.json"))
        trial["automated_preliminary_outcome"] = trial["preliminary_outcome"]
        trial["outcome"] = review["outcome"]
        trial["review_required"] = False
        trial["review"] = review
        (directory / "trial.json").write_text(json.dumps(trial, indent=2, ensure_ascii=False), encoding="utf-8")
        added.append(row)
    rows.extend(added)
    metrics = summarize(rows)
    with ledger.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (ROOT / "results/metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"recorded": len(added), "total": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
