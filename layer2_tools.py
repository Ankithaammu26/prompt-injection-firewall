"""Layer 2: tool-level security (permissions, argument validation, task relevance, influence)."""
import re, json


POLICY = {
    "read_file":  {"sensitive": False},
    "web_fetch":  {"sensitive": False},
    "send_email": {"sensitive": True, "allowed_recipient_domains": ["company.com"]},
    "delete_file": {"sensitive": True, "always_review": True},
}


def validate_tool_call(task, tool, args, ctx):
    """Returns (decision, reasons). Hard rules first, then relevance, then influence."""
    reasons = []
    pol = POLICY.get(tool)
    if pol is None:
        return "BLOCK", ["tool not in policy"]
    if pol.get("always_review"):
        return "REVIEW", ["irreversible action requires approval"]
    # permission / argument validation (hard rule - cannot be overridden by user approval)
    if tool == "send_email":
        to = args.get("to", "")
        dom = to.split("@")[-1] if "@" in to else ""
        if dom not in pol["allowed_recipient_domains"]:
            reasons.append(f"recipient domain '{dom}' not allowed")
            return "BLOCK", reasons
    # influence from flagged content
    inf = ctx.influence(args)
    if inf["linked"]:
        return "BLOCK", [f"arguments match flagged content from {inf['source']}: {inf['shared']}"]
    # task relevance (LLM_HOOK: replace with Task-Shield style LLM check)
    words = set(re.findall(r"\w{4,}", task.lower()))
    tool_words = set(re.findall(r"\w{4,}", tool.replace("_", " ") + " " + json.dumps(args).lower()))
    if pol["sensitive"] and not (words & tool_words):
        return "REVIEW", ["sensitive tool with weak relation to user task"]
    return "ALLOW", ["passed policy, relevance and influence checks"]