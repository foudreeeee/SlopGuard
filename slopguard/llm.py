"""LLM provider seam.

The one place a vendor SDK is imported. The rest of the code — and every test —
calls `complete()` and never sees the provider, so swapping Anthropic for
another backend is a change to this file alone.

The whole LLM pass is optional: no key configured -> `complete()` raises
`LLMUnavailableError` and the caller falls back to the static-only result.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "claude-haiku-4-5-20251001"

_KEY_ENV = ("SLOPGUARD_LLM_API_KEY", "ANTHROPIC_API_KEY")
_MODEL_ENV = "SLOPGUARD_LLM_MODEL"


class LLMUnavailableError(RuntimeError):
    """No usable LLM backend (missing key or SDK). Caller degrades gracefully."""


def _api_key() -> str | None:
    for name in _KEY_ENV:
        key = os.environ.get(name)
        if key:
            return key
    return None


def available() -> bool:
    """True if a key is set. Does not check the SDK (that's a lazy import)."""
    return _api_key() is not None


def complete(system: str, user: str, *, max_tokens: int = 1024) -> str:
    """Send one grounded prompt and return the raw text response.

    Temperature 0 to keep triage as reproducible as an LLM allows.
    """
    key = _api_key()
    if key is None:
        raise LLMUnavailableError(
            "no API key set (SLOPGUARD_LLM_API_KEY or ANTHROPIC_API_KEY)"
        )
    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailableError(
            "anthropic SDK not installed; run: pip install 'slopguard[llm]'"
        ) from exc

    client = anthropic.Anthropic(api_key=key)
    response = client.messages.create(
        model=os.environ.get(_MODEL_ENV, DEFAULT_MODEL),
        max_tokens=max_tokens,
        temperature=0,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )
