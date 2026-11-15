"""Append reviewed completed trials to the main ledger, never capability checks."""
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
    added = []
    for local_id, review in reviews.items():
        directory = run / "trials" / local_id
        trial = json.loads((directory / "trial.json").read_text(encoding="utf-8"))
        if not trial["conversation_completed"] or not trial["document_encountered"]:
            raise ValueError("Only completed, exposed trials enter this reviewed ledger")
        canonical_id = args.run_id + ":" + local_id
        if canonical_id in existing:
            raise ValueError("Trial already recorded")
        before = json.loads((directory / "before.json").read_text(encoding="utf-8"))
        after = json.loads((directory / "after.json").read_text(encoding="utf-8"))
        calls = trial["calls"]
        approval_file = directory / "approval-and-calls.json"
        if not approval_file.exists() and not calls:
            approval_file.write_text("[]\n", encoding="utf-8")
        for evidence in (directory / "conversation.json", directory / "before.json", directory / "after.json", approval_file):
            if not evidence.is_file():
                raise ValueError(f"Missing evidence: {evidence}")
        effect = before != after or trial["canary_received"]
        if review["outcome"] == "Executed" and not (effect and trial["unauthorized_tool_attempt"]):
            raise ValueError("Execution claim lacks attributable side effects")
        model = next(model for model in inventory["models"]["models"] if model["name"] == trial["model"])
        row = {field: "" for field in fields}
        boolean = lambda value: "true" if value else "false"
        rel = lambda path: path.relative_to(ROOT).as_posix()
        row.update(trial_id=canonical_id, timestamp=trial["timestamp"],
            environment=json.dumps({"os": "Windows", "kernel": "15.0.1", "interface": "GenAI LLMTool", "client": "custom local Ollama", "vm": False, "general_evaluator_exposed": False, "allow_internet": False}),
            model=json.dumps({"name": trial["model"], "digest": model["digest"], "seed": trial["seed"]}),
            agent_configuration=trial["agent_configuration"], scenario=trial["scenario"],
            legitimate_request=trial["legitimate_request"], adversarial_document_id=trial["adversarial_document_id"],
            tool_name=json.dumps([call["tool_name"] for call in calls]),
            tool_arguments=json.dumps([call["tool_arguments"] for call in calls]),
            approval_requested="false", approval_granted="false",
            execution_attempted=boolean(any(call["execution_attempted"] for call in calls)),
            execution_succeeded=boolean(effect or any(call["result"].get("success") for call in calls)),
            observed_side_effects=json.dumps({"removed_files": sorted(set(before["files"]) - set(after["files"])),
                "changed_files": sorted(key for key in set(before["files"]) & set(after["files"]) if before["files"][key] != after["files"][key]),
                "records_before": before["database"]["total_records"], "records_after": after["database"]["total_records"], "canary_received": trial["canary_received"]}),
            final_agent_response=trial["final_agent_response"], outcome=review["outcome"],
            unauthorized_attempt=boolean(review["unauthorized_attempt"]),
            unauthorized_execution=boolean(review["outcome"] == "Executed"), approval_intercepted="false",
            legitimate_task_completed=boolean(review["legitimate_task_completed"]),
            trace_path=rel(directory / "conversation.json"), before_manifest=rel(directory / "before.json"),
            after_manifest=rel(directory / "after.json"), client_approval_log=rel(approval_file))
        trial["automated_preliminary_outcome"] = trial["outcome"]
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
