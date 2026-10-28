"""Provider credentials and direct, provider-neutral model calls.

Keys never enter agent messages, API responses, or MCP child environments.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, SecretStr

from .config import settings


PROVIDERS = {
    "ollama": {"base_url": "https://ollama.com", "model": ""},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "model": ""},
}
router = APIRouter(prefix="/api/providers", tags=["providers"])


class ProviderError(Exception):
    """A sanitized provider failure safe to show to the analyst."""


class ProviderUpdate(BaseModel):
    api_key: SecretStr | None = None
    model: str = Field(default="", max_length=200)


class ProviderStore:
    def __init__(self, data_dir: Path | None = None):
        self.directory = Path(data_dir or settings.data_dir)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = self.directory / "state.db"
        with self.connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS provider_settings (id TEXT PRIMARY KEY, model TEXT NOT NULL, encrypted_key TEXT)")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.database, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        os.chmod(self.database, 0o600)
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def cipher(self) -> Fernet:
        path = self.directory / ".provider-key"
        if not path.exists():
            # Publish only a fully written key. O_EXCL on the final filename
            # would expose an empty file to concurrent first-use requests.
            fd, temporary = tempfile.mkstemp(prefix=".provider-key-", dir=self.directory)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(Fernet.generate_key())
                    output.flush()
                    os.fsync(output.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass  # Another creator's complete key won the race.
            finally:
                Path(temporary).unlink(missing_ok=True)
        os.chmod(path, 0o600)
        return Fernet(path.read_bytes())

    def get(self, provider: str, *, include_key: bool = False) -> dict:
        if provider not in PROVIDERS:
            raise ValueError("Unknown provider")
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM provider_settings WHERE id=?", (provider,)).fetchone()
        result = {"id": provider, "configured": bool(row and row["encrypted_key"]), "model": row["model"] if row else "", "base_url": PROVIDERS[provider]["base_url"]}
        if include_key:
            result["api_key"] = None
            if row and row["encrypted_key"]:
                try:
                    result["api_key"] = self.cipher().decrypt(row["encrypted_key"].encode()).decode()
                except (InvalidToken, ValueError, OSError):
                    raise ProviderError("Saved credentials could not be decrypted. Enter the provider key again.") from None
        return result

    def update(self, provider: str, model: str, api_key: str | None = None) -> dict:
        self.get(provider)
        if any(ord(c) < 32 for c in model):
            raise ValueError("Model ID contains invalid characters")
        with self.connect() as connection:
            old = connection.execute("SELECT encrypted_key FROM provider_settings WHERE id=?", (provider,)).fetchone()
            encrypted = old[0] if old else None
            if api_key is not None:
                key = api_key.strip()
                if len(key) > 4096 or any(ord(c) < 32 for c in key):
                    raise ValueError("Invalid API key")
                encrypted = self.cipher().encrypt(key.encode()).decode() if key else None
            connection.execute("INSERT INTO provider_settings(id,model,encrypted_key) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET model=excluded.model, encrypted_key=excluded.encrypted_key", (provider, model.strip(), encrypted))
        return self.get(provider)


class ProviderClient:
    def __init__(self, provider: str, api_key: str, model: str, transport: httpx.AsyncBaseTransport | None = None):
        if provider not in PROVIDERS:
            raise ProviderError("Unknown model provider")
        self.provider, self.api_key, self.model = provider, api_key, model
        self.transport = transport
        self.thinking: str | bool | None = None

    async def request(self, method: str, path: str, body: dict | None = None, *, timeout: int = 90) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.provider == "openrouter":
            headers["X-Title"] = "Ghidrama"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=15), transport=self.transport, follow_redirects=False) as client:
                response = await client.request(method, PROVIDERS[self.provider]["base_url"] + path, headers=headers, json=body)
            if response.status_code in (401, 403):
                raise ProviderError("The provider rejected the API key or access to this model.")
            if response.status_code == 429:
                raise ProviderError("Provider rate or account limit reached. Wait and try again.")
            if self.provider == "ollama" and response.status_code == 404:
                raise ProviderError("Ollama Cloud could not find the selected model. Fetch models in Model connections and select an exact catalog ID; local Ollama :cloud and -cloud aliases may not work with the cloud API.")
            if response.status_code >= 500:
                raise ProviderError(f"The model provider is temporarily unavailable (HTTP {response.status_code}). Try again shortly.")
            if response.status_code >= 400:
                raise ProviderError(f"Provider request failed (HTTP {response.status_code}). Check the model ID, account balance, and model tool support.")
            if len(response.content) > 4 * 1024 * 1024:
                raise ProviderError("Provider response exceeded the size limit.")
            result = response.json()
            if not isinstance(result, dict) or result.get("error"):
                raise ProviderError("Provider returned an invalid response.")
            return result
        except httpx.TimeoutException:
            raise ProviderError("The model provider did not respond in time. Try again shortly.") from None
        except httpx.NetworkError:
            raise ProviderError("Could not reach the model provider. Check the connection and try again.") from None
        except (ValueError, httpx.HTTPError):
            raise ProviderError("Provider returned an unreadable response.") from None

    async def models(self) -> list[dict]:
        payload = await self.request("GET", "/api/tags" if self.provider == "ollama" else "/models")
        entries = payload.get("models" if self.provider == "ollama" else "data", [])
        if not isinstance(entries, list):
            raise ProviderError("Provider returned an invalid model catalog.")
        result = []
        for entry in entries[:10000]:
            if not isinstance(entry, dict):
                continue
            model_id = entry.get("model") or entry.get("id") or entry.get("name")
            if isinstance(model_id, str):
                result.append({"id": model_id, "name": entry.get("name", model_id)})
        return result

    async def test(self) -> str:
        if self.provider == "openrouter":
            await self.request("GET", "/key")
            return "API key verified. Model tool support is checked when an investigation runs."
        if not self.model:
            raise ProviderError("Choose an Ollama cloud model before testing the connection.")
        response = await self.request("POST", "/api/chat", {"model": self.model, "messages": [{"role": "user", "content": "Reply OK."}], "stream": False, "options": {"num_predict": 4}})
        if not isinstance(response.get("message"), dict) or not isinstance(response["message"].get("content"), str):
            raise ProviderError("Ollama Cloud did not return a usable test response.")
        return "Connected. The selected Ollama model answered a short test request."

    async def chat(self, messages: list[dict], tools: list[dict], *, max_output_tokens: int = 4096) -> dict:
        if not self.model:
            raise ProviderError("Choose a model in provider settings first.")
        if not 1 <= max_output_tokens <= 16384:
            raise ProviderError("Invalid model output-token allowance.")
        if self.provider == "openrouter":
            wire_messages = [{key: value for key, value in message.items() if key not in ("tool_name", "thinking")} for message in messages]
            payload = {"model": self.model, "messages": wire_messages, "stream": False, "max_tokens": max_output_tokens,
                       "provider": {"require_parameters": True, "data_collection": "deny"}}
            if tools:
                payload["tools"] = tools
            response = await self.request("POST", "/chat/completions", payload, timeout=180 if max_output_tokens > 4096 else 90)
            choices = response.get("choices", [])
            if not choices or not isinstance(choices[0].get("message"), dict):
                raise ProviderError("The model did not return a usable answer.")
            message = choices[0]["message"]
            truncated = choices[0].get("finish_reason") == "length"
            usage = response.get("usage", {})
            calls = message.get("tool_calls") or []
        else:
            native_messages = []
            for message in messages:
                item = {"role": message["role"], "content": message.get("content") or ""}
                if message.get("thinking"):
                    item["thinking"] = message["thinking"]
                if message.get("tool_calls"):
                    item["tool_calls"] = []
                    for call in message["tool_calls"]:
                        arguments = call["function"]["arguments"]
                        if isinstance(arguments, str):
                            try:
                                arguments = json.loads(arguments)
                            except ValueError:
                                arguments = {}
                        item["tool_calls"].append({"function": {"name": call["function"]["name"], "arguments": arguments}})
                if message.get("tool_name"):
                    item["tool_name"] = message["tool_name"]
                native_messages.append(item)
            payload = {"model": self.model, "messages": native_messages, "stream": False, "options": {"num_predict": max_output_tokens}}
            if self.thinking is not None:
                payload["think"] = self.thinking
            if tools:
                payload["tools"] = tools
            response = await self.request("POST", "/api/chat", payload, timeout=180 if max_output_tokens > 4096 else 90)
            message = response.get("message")
            truncated = response.get("done_reason") == "length"
            if not isinstance(message, dict):
                raise ProviderError("The model did not return a usable answer.")
            usage = {"prompt_tokens": response.get("prompt_eval_count", 0), "completion_tokens": response.get("eval_count", 0)}
            calls = message.get("tool_calls") or []
        if not isinstance(calls, list) or not isinstance(usage, dict):
            raise ProviderError("Provider returned invalid tool calls or usage data.")
        normalized = []
        for index, call in enumerate(calls[:32]):
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                raise ProviderError("Provider returned a malformed tool call.")
            function = call.get("function", {})
            arguments = function.get("arguments", {})
            normalized.append({"id": str(call.get("id", f"call_{index}")), "type": "function", "function": {"name": str(function.get("name", "")), "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)}})
        try:
            counts = {"input_tokens": max(0, int(usage.get("prompt_tokens") or 0)), "output_tokens": max(0, int(usage.get("completion_tokens") or 0))}
        except (ValueError, TypeError, OverflowError):
            raise ProviderError("Provider returned invalid usage data.") from None
        private_context = {}
        if self.provider == "ollama" and isinstance(message.get("thinking"), str):
            private_context["thinking"] = message["thinking"]
        if self.provider == "openrouter" and isinstance(message.get("reasoning_details"), list):
            private_context["reasoning_details"] = message["reasoning_details"]
        return {"role": "assistant", "content": str(message.get("content") or "")[:40000], "tool_calls": normalized,
                "usage": counts, "private_context": private_context,
                "truncated": truncated or len(str(message.get("content") or "")) > 40000}


def configured_client(provider: str, model: str | None = None) -> ProviderClient:
    try:
        item = ProviderStore().get(provider, include_key=True)
    except ValueError:
        raise HTTPException(404, "Unknown provider") from None
    if not item["api_key"]:
        raise HTTPException(400, "Add an API key in provider settings first.")
    return ProviderClient(provider, item["api_key"], model or item["model"])


@router.get("")
def list_providers():
    store = ProviderStore()
    return [store.get(provider) for provider in PROVIDERS]


@router.put("/{provider}")
def update_provider(provider: str, body: ProviderUpdate):
    try:
        return ProviderStore().update(provider, body.model, body.api_key.get_secret_value() if body.api_key is not None else None)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.post("/{provider}/test")
async def test_provider(provider: str):
    try:
        message = await configured_client(provider).test()
        return {"ok": True, "message": message}
    except ProviderError as exc:
        return {"ok": False, "message": str(exc)}


@router.get("/{provider}/models")
async def list_models(provider: str):
    try:
        # Ollama's hosted catalog is public. Discover models before asking the
        # analyst to save credentials, and do not send a key to this endpoint.
        client = ProviderClient("ollama", "", "") if provider == "ollama" else configured_client(provider)
        return await client.models()
    except ProviderError as exc:
        raise HTTPException(502, str(exc)) from None
