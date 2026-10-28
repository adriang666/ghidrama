"""Investigation budgets count cumulative provider usage, not context capacity."""
from __future__ import annotations

import json
import math

DEFAULT_BUDGET = "extended"
BUDGETS = {
    "standard": {"total_tokens": 80_000, "model_turns": 12, "tool_calls": 32, "seconds": 240},
    "extended": {"total_tokens": 250_000, "model_turns": 24, "tool_calls": 64, "seconds": 600},
    "deep": {"total_tokens": 500_000, "model_turns": 40, "tool_calls": 100, "seconds": 900},
}
MAX_OUTPUT_TOKENS = 4096
PSEUDOCODE_OUTPUT_TOKENS = 12288


def request_size(messages: list[dict], tools: list[dict]) -> int:
    return len(json.dumps({"messages": messages, "tools": tools}, ensure_ascii=False).encode("utf-8"))


def estimate_prompt_tokens(messages: list[dict], tools: list[dict], previous_tokens: int = 0, previous_size: int = 0) -> int:
    """Conservative estimate, calibrated to actual usage from the previous call.

    Providers tokenize differently. This is admission control, not an exact
    tokenizer or a billing guarantee. Never discard source evidence to fit it.
    """
    size = request_size(messages, tools)
    estimate = math.ceil(size / 3) + 256
    if previous_tokens > 0 and previous_size > 0:
        estimate = max(estimate, math.ceil(previous_tokens * size / previous_size * 1.1) + 256)
    return estimate


def finishing_reason(limits: dict, *, used: int, prompt_tokens: int, turns: int, tools: int, seconds_left: float, output_tokens: int = MAX_OUTPUT_TOKENS) -> str | None:
    # Reserve space for a final answer plus one citation correction. Winding
    # down before another exploratory call avoids spending everything on tools.
    if used + 3 * (prompt_tokens + output_tokens + 512) >= limits["total_tokens"]:
        return f"Approaching the {limits['total_tokens']:,}-token investigation budget; finishing with the evidence already gathered."
    if turns >= limits["model_turns"] - 2:
        return "Approaching the model-turn limit; finishing with the evidence already gathered."
    if tools >= limits["tool_calls"] - 2:
        return "Approaching the tool-call limit; finishing with the evidence already gathered."
    if seconds_left <= (185 if output_tokens > MAX_OUTPUT_TOKENS else 95):
        return "Approaching the investigation time limit; finishing with the evidence already gathered."
    return None
