"""Cross-Layer Threat Context Manager: links flagged content to later tool calls."""
import re, json
from dataclasses import dataclass, field
from layer1_content import EMAIL, URL


@dataclass
class ThreatContext:
    records: list = field(default_factory=list)

    def add(self, source, seg):
        self.records.append({"source": source, "text": seg["text"], "score": seg["score"],
                             "tokens": set(EMAIL.findall(seg["text"]) + URL.findall(seg["text"])
                                           + re.findall(r"\w{5,}", seg["text"].lower()))})

    def influence(self, tool_args):
        """Does this tool call reuse entities from flagged content?"""
        arg_txt = json.dumps(tool_args).lower()
        arg_ents = set(EMAIL.findall(arg_txt) + URL.findall(arg_txt))
        for rec in self.records:
            shared_ents = arg_ents & {t.lower() for t in rec["tokens"]}
            if shared_ents:
                return {"linked": True, "source": rec["source"], "shared": sorted(shared_ents)}
        return {"linked": False}