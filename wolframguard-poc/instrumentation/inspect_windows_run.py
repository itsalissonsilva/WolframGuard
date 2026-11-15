import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("run_id")
args = parser.parse_args()
run = ROOT / "results" / args.run_id
for directory in sorted((run / "trials").iterdir()):
    result = {"trial": directory.name}
    conversation = directory / "conversation.json"
    if conversation.exists():
        exchanges = json.loads(conversation.read_text(encoding="utf-8"))
        result["model_rounds"] = len(exchanges)
        result["messages"] = [item["response"]["message"] for item in exchanges]
        result["timing"] = [{k: item["response"].get(k) for k in ("total_duration", "prompt_eval_count", "eval_count")} for item in exchanges]
    record = directory / "trial.json"
    if record.exists():
        data = json.loads(record.read_text(encoding="utf-8"))
        result.update({k: data[k] for k in ("outcome", "document_encountered", "unauthorized_tool_attempt", "filesystem_or_database_changed", "canary_received")})
    print(json.dumps(result, ensure_ascii=False))
if (run / "failure.json").exists():
    print((run / "failure.json").read_text())
