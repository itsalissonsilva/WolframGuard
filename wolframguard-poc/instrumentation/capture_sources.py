"""Capture installed vendor code excerpts and hashes, not user configuration."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = pathlib.Path(r"C:\Users\Lenovo\AppData\Roaming\Wolfram\Paclets\Repository\Wolfram__AgentTools-2.2.0")
CHAT = AGENT.parent / "Wolfram__Chatbook-2.7.0"
LLM = pathlib.Path(r"C:\Program Files\Wolfram Research\Wolfram\15.0\SystemFiles\Components\LLMFunctions")
SOURCES = [
    (AGENT / "PacletInfo.wl", [(1, 18)]),
    (AGENT / "Kernel/Tools/WolframLanguageEvaluator.wl", [(30, 47), (94, 106), (145, 174)]),
    (AGENT / "Kernel/Server/Shared.wl", [(419, 436), (755, 778)]),
    (AGENT / "Kernel/Server/Local.wl", [(37, 103)]),
    (AGENT / "Kernel/SupportedClients.wl", [(429, 442)]),
    (AGENT / "Kernel/MCPServerObject.wl", [(14, 21)]),
    (AGENT / "Kernel/DefaultServers.wl", [(30, 48)]),
    (AGENT / "Documentation/English/ReferencePages/Symbols/InstallMCPServer.nb", [(18737, 18766)]),
    (CHAT / "Source/Chatbook/Sandbox.wl", [(525, 553), (592, 638), (987, 1000), (1304, 1332)]),
    (LLM / "Kernel/Chat.wl", [(891, 910)]),
    (LLM / "Kernel/Tools/LLMToolResponse.wl", [(140, 166)]),
]

def main():
    records = []
    for path, ranges in SOURCES:
        raw = path.read_bytes()
        lines = raw.decode("utf-8-sig").splitlines()
        records.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                        "excerpts": [{"start": start, "end": end,
                                      "lines": [{"line": i + 1, "text": lines[i]}
                                                for i in range(start - 1, min(end, len(lines)))]}
                                     for start, end in ranges]})
    output = ROOT / "results/discovery/source-evidence.json"
    rendered = json.dumps(records, indent=2)
    if output.exists() and output.read_text(encoding="utf-8") != rendered:
        raise SystemExit("Source evidence changed; preserve the baseline and select a new evidence filename")
    output.write_text(rendered, encoding="utf-8")
    print(f"Captured {len(records)} installed-source records: {output}")

if __name__ == "__main__":
    main()
