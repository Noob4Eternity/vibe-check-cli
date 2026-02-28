"""Async LLM client with multi-provider support and token budget enforcement."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("vibe_check.llm_client")


class TokenBudgetExceeded(Exception):
    """Raised when cumulative token usage exceeds the configured budget."""
    pass


@dataclass
class LLMClient:
    """Async LLM client supporting Gemini (default), OpenAI, and Anthropic.

    Tracks cumulative token usage and enforces a per-scan budget.

    Usage:
        client = LLMClient(provider="gemini")  # reads GEMINI_API_KEY from env
        response = await client.ask("Is this a vulnerability?", max_tokens=200)
        print(client.tokens_used)
    """

    provider: str = "gemini"
    api_key: Optional[str] = None
    model: Optional[str] = None
    budget: int = 5000
    max_retries: int = 3

    _tokens_used: int = field(default=0, init=False, repr=False)
    _call_count: int = field(default=0, init=False, repr=False)
    _client: object = field(default=None, init=False, repr=False)

    ENV_KEYS = {
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }

    DEFAULT_MODELS = {
        "gemini": "gemini-2.5-pro",
        "openai": "gpt-4o",
        "anthropic": "claude-sonnet-4-20250514",
    }

    def __post_init__(self) -> None:
        if self.api_key is None:
            env_var = self.ENV_KEYS.get(self.provider, "GEMINI_API_KEY")
            self.api_key = os.environ.get(env_var)
            if not self.api_key:
                raise ValueError(
                    f"No API key. Set {env_var} env var or pass api_key="
                )

        if self.model is None:
            self.model = self.DEFAULT_MODELS.get(self.provider, "gemini-2.5-pro")

        self._init_client()

    def _init_client(self) -> None:
        if self.provider == "gemini":
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                raise ImportError("pip install google-genai")

        elif self.provider == "openai":
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("pip install openai")

        elif self.provider == "anthropic":
            try:
                from anthropic import AsyncAnthropic
                self._client = AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("pip install anthropic")

        else:
            raise ValueError(
                f"Unknown provider '{self.provider}'. Use 'gemini', 'openai', or 'anthropic'."
            )

    # -- Public properties ---------------------------------------------------

    @property
    def tokens_used(self) -> int:
        return self._tokens_used

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.budget - self._tokens_used)

    @property
    def call_count(self) -> int:
        return self._call_count

    # -- Core method ---------------------------------------------------------

    async def ask(self, prompt: str, max_tokens: int = 500) -> str:
        """Send a prompt and return the response text.

        Raises TokenBudgetExceeded if the budget is already exhausted.
        Retries with exponential backoff on transient failures.
        """
        if self._tokens_used >= self.budget:
            raise TokenBudgetExceeded(
                f"Token budget exhausted: {self._tokens_used}/{self.budget} used"
            )

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                text, in_tok, out_tok = await self._call_provider(
                    prompt, max_tokens
                )

                self._tokens_used += in_tok + out_tok
                self._call_count += 1

                logger.info(
                    "LLM #%d | %s/%s | in=%d out=%d | budget %d/%d",
                    self._call_count,
                    self.provider,
                    self.model,
                    in_tok,
                    out_tok,
                    self._tokens_used,
                    self.budget,
                )

                if self._tokens_used > self.budget:
                    logger.warning(
                        "Budget exceeded after call: %d/%d",
                        self._tokens_used,
                        self.budget,
                    )

                return text

            except TokenBudgetExceeded:
                raise
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    logger.warning(
                        "LLM call failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1,
                        self.max_retries,
                        e,
                        wait,
                    )
                    await asyncio.sleep(wait)

        raise last_error  # type: ignore[misc]

    # -- Provider dispatch ---------------------------------------------------

    async def _call_provider(
        self, prompt: str, max_tokens: int
    ) -> tuple[str, int, int]:
        """Returns (response_text, input_tokens, output_tokens)."""
        if self.provider == "gemini":
            return await self._call_gemini(prompt, max_tokens)
        elif self.provider == "openai":
            return await self._call_openai(prompt, max_tokens)
        elif self.provider == "anthropic":
            return await self._call_anthropic(prompt, max_tokens)
        raise ValueError(f"Unknown provider: {self.provider}")

    async def _call_gemini(
        self, prompt: str, max_tokens: int
    ) -> tuple[str, int, int]:
        from google.genai import types

        response = await self._client.aio.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
            ),
        )

        text = response.text or ""
        usage = response.usage_metadata
        return (
            text,
            usage.prompt_token_count or 0,
            usage.candidates_token_count or 0,
        )

    async def _call_openai(
        self, prompt: str, max_tokens: int
    ) -> tuple[str, int, int]:
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )

        text = response.choices[0].message.content or ""
        return (
            text,
            response.usage.prompt_tokens or 0,
            response.usage.completion_tokens or 0,
        )

    async def _call_anthropic(
        self, prompt: str, max_tokens: int
    ) -> tuple[str, int, int]:
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text if response.content else ""
        return (
            text,
            response.usage.input_tokens or 0,
            response.usage.output_tokens or 0,
        )
