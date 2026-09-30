"""LLM provider seam.

The one place a vendor SDK is imported. The rest of the code — and every test —
calls `complete()` and never sees the provider, so adding or swapping a backend
is a change to this file alone.

Two backends:
  - anthropic (default): hosted Claude. Needs a key.
  - openai: any OpenAI-compatible endpoint. Point SLOPGUARD_LLM_BASE_URL at a
    local runtime (Ollama, llama.cpp, LM Studio, vLLM) to run fully local with
    no key and no per-call cost, or leave it unset to use hosted OpenAI.

Config (all via env):
  SLOPGUARD_LLM_PROVIDER   anthropic | openai        (default: anthropic)
  SLOPGUARD_LLM_MODEL      model id                  (required for openai)
  SLOPGUARD_LLM_BASE_URL   OpenAI-compatible base url (e.g. a local Ollama)
  SLOPGUARD_LLM_API_KEY    key, or ANTHROPIC_API_KEY / OPENAI_API_KEY

The whole pass is optional: nothing usable configured -> `complete()` raises
`LLMUnavailableError` and the caller falls back to the static-only result.
"""

from __future__ import annotations

import os

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

_PROVIDER_ENV = "SLOPGUARD_LLM_PROVIDER"
_MODEL_ENV = "SLOPGUARD_LLM_MODEL"
_BASE_URL_ENV = "SLOPGUARD_LLM_BASE_URL"
_ANTHROPIC_KEYS = ("SLOPGUARD_LLM_API_KEY", "ANTHROPIC_API_KEY")
_OPENAI_KEYS = ("SLOPGUARD_LLM_API_KEY", "OPENAI_API_KEY")


class LLMUnavailableError(RuntimeError):
    """No usable LLM backend (missing key, SDK, or config). Caller degrades."""


def _provider() -> str:
    return os.environ.get(_PROVIDER_ENV, "anthropic").strip().lower()


def _first_env(names: tuple[str, ...]) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def available() -> bool:
    """True if the configured provider looks usable. Does not import any SDK."""
    if _provider() == "openai":
        # a local endpoint needs only a base url; hosted OpenAI needs a key
        return bool(os.environ.get(_BASE_URL_ENV) or _first_env(_OPENAI_KEYS))
    return _first_env(_ANTHROPIC_KEYS) is not None


def complete(system: str, user: str, *, max_tokens: int = 1024) -> str:
    """Send one grounded prompt and return the raw text. Temperature 0 so
    triage is as reproducible as an LLM allows."""
    if _provider() == "openai":
        return _complete_openai(system, user, max_tokens)
    return _complete_anthropic(system, user, max_tokens)


def _complete_anthropic(system: str, user: str, max_tokens: int) -> str:
    key = _first_env(_ANTHROPIC_KEYS)
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
        model=os.environ.get(_MODEL_ENV, DEFAULT_ANTHROPIC_MODEL),
        max_tokens=max_tokens,
        temperature=0,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )


def _complete_openai(system: str, user: str, max_tokens: int) -> str:
    model = os.environ.get(_MODEL_ENV)
    if not model:
        raise LLMUnavailableError(
            f"set {_MODEL_ENV} for the openai provider "
            "(e.g. 'llama3.1' for a local Ollama, or a hosted OpenAI model)"
        )
    base_url = os.environ.get(_BASE_URL_ENV)
    # a local OpenAI-compatible endpoint needs no real key
    key = _first_env(_OPENAI_KEYS) or ("local" if base_url else None)
    if key is None:
        raise LLMUnavailableError(
            "no API key set (SLOPGUARD_LLM_API_KEY or OPENAI_API_KEY) and no "
            "SLOPGUARD_LLM_BASE_URL for a local endpoint"
        )
    try:
        import openai
    except ImportError as exc:
        raise LLMUnavailableError(
            "openai SDK not installed; run: pip install 'slopguard[llm]'"
        ) from exc

    client = openai.OpenAI(api_key=key, base_url=base_url or None)
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return response.choices[0].message.content or ""
