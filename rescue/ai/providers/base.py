from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass


class AIProviderUnavailable(Exception):
    """Raised when a provider's SDK isn't installed or the provider can't be constructed."""


class AIRequestError(Exception):
    """Raised when a configured provider's request to the model fails."""


@dataclass
class AIMessage:
    role: str
    content: str


class AIProvider(ABC):
    """Strategy interface for AI backends. Every backend need only implement `complete`;
    `complete_async` is provided for free by running `complete` in a worker thread, so
    every provider is usable from both sync and async call sites."""

    provider_name: str

    @abstractmethod
    def complete(self, messages: list[AIMessage], system: str | None = None) -> str:
        """Send messages to the model and return its text response. Synchronous."""

    async def complete_async(
        self, messages: list[AIMessage], system: str | None = None
    ) -> str:
        return await asyncio.to_thread(self.complete, messages, system)
