"""Layer 1: context-aware content analysis (segmentation, instruction detection, cross-segment check)."""
import re

INSTR = re.compile(
    r"\b(ignore (all |any )?(previous|prior|above) (instructions|prompts?)|"
    r"disregard .{0,30}(instructions|task)|you (must|should|will) now|"
    r"new instructions?|system prompt|do not (tell|inform|mention)|"
    r"forward .{0,40}(to|@)|send .{0,60}(to|@)|"
    r"(delete|transfer|upload|exfiltrate|reveal) )", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]*\w")
URL = re.compile(r"https?://[^\s\"'<>)]+")
AGENT_ADDR = re.compile(r"\b(assistant|ai|agent|llm|model|claude|gpt)\b", re.I)
QUOTE_CTX = re.compile(r"(for example|e\.g\.|such as|an attacker (may|might|could)|"
                       r"attacks? (like|such as)|the phrase|injection (looks|example))", re.I)
# weak signals used for cross-segment detection
WEAK_ACTION = re.compile(r"\b(send|forward|share|email|upload|post|copy)\b", re.I)
WEAK_TARGET = re.compile(r"(@[\w-]+\.[\w.]+|https?://|all (files|contacts|emails|passwords))", re.I)


def segment(text):
    """Split into paragraph/sentence segments with character offsets."""
    segs, pos = [], 0
    for para in re.split(r"\n\s*\n|\n", text):
        for sent in re.split(r"(?<=[.!?])\s+", para):
            if sent.strip():
                start = text.find(sent, pos)
                segs.append({"text": sent.strip(), "start": start, "end": start + len(sent)})
                pos = max(pos, start + len(sent))
    return segs


def analyze_segment(seg, source_trust):
    """LLM_HOOK: replace with an LLM call returning {label, confidence}."""
    t = seg["text"]
    hit = bool(INSTR.search(t))
    quoted = bool(QUOTE_CTX.search(t)) or (t.count('"') >= 2 and hit)
    score = 0.0
    if hit: score += 0.6
    if AGENT_ADDR.search(t) and hit: score += 0.2
    if EMAIL.search(t) or URL.search(t): score += 0.1 if hit else 0.0
    if source_trust == "untrusted": score += 0.1
    if quoted: score -= 0.5           # context: quoted/explained, not active
    label = "malicious" if score >= 0.6 else "quoted_or_benign" if hit else "benign"
    return {**seg, "score": round(score, 2), "label": label, "quoted": quoted}


def cross_segment(results):
    """Detect an objective split across segments (action in one, target in another)."""
    flagged = []
    for i, r in enumerate(results):
        if r["label"] != "benign": continue
        window = results[i:i + 3]
        txt = " ".join(w["text"] for w in window)
        if WEAK_ACTION.search(txt) and WEAK_TARGET.search(txt) and AGENT_ADDR.search(txt):
            for w in window:
                if w["label"] == "benign" and (WEAK_ACTION.search(w["text"]) or WEAK_TARGET.search(w["text"])):
                    w["label"], w["score"] = "malicious", 0.65
                    w["reason"] = "cross-segment"
                    flagged.append(w)
    return results