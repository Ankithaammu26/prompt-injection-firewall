"""Layer 3: safe response - sanitized view, audit log, and the Firewall that ties all layers together."""
import json, sqlite3, time
from layer1_content import segment, analyze_segment, cross_segment
from threat_context import ThreatContext
from layer2_tools import validate_tool_call


class AuditLog:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS log(
            ts REAL, kind TEXT, source TEXT, detail TEXT, decision TEXT)""")

    def write(self, kind, source, detail, decision):
        self.db.execute("INSERT INTO log VALUES (?,?,?,?,?)",
                        (time.time(), kind, source, detail, decision))
        self.db.commit()

    def dump(self):
        return self.db.execute("SELECT kind,source,detail,decision FROM log").fetchall()


class Firewall:
    def __init__(self, db_path=":memory:"):
        self.ctx, self.log = ThreatContext(), AuditLog(db_path)

    def scan_content(self, text, source, trust="untrusted"):
        """Layer 1 + Layer 3 sanitized view. Original text is never modified."""
        res = cross_segment([analyze_segment(s, trust) for s in segment(text)])
        sanitized, removed = text, []
        for r in sorted(res, key=lambda r: -r["start"]):
            if r["label"] == "malicious":
                self.ctx.add(source, r)
                removed.append(r["text"])
                sanitized = sanitized[:r["start"]] + "[REMOVED: suspected injection]" + sanitized[r["end"]:]
                self.log.write("content_flag", source, r["text"], "SANITIZED")
            elif r["label"] == "quoted_or_benign" and r["score"] > 0:
                self.log.write("content_note", source, r["text"], "KEPT (quoted/contextual)")
        return {"original": text, "sanitized": sanitized, "removed": removed, "segments": res}

    def check_tool(self, task, tool, args):
        decision, reasons = validate_tool_call(task, tool, args, self.ctx)
        self.log.write("tool_call", tool, json.dumps(args) + " | " + "; ".join(reasons), decision)
        return decision, reasons