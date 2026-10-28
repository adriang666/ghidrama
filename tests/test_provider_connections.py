"""Connection setup regressions; provider traffic is mocked."""
import httpx
import pytest
from fastapi.testclient import TestClient

from ghidrama import providers
from ghidrama.config import settings
from ghidrama.main import app
from ghidrama.providers import ProviderClient, ProviderError, ProviderStore


def test_ollama_catalog_is_available_without_saving_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    requests = []

    def catalog(request):
        requests.append(request)
        return httpx.Response(200, json={"models": [{"name": "gpt-oss:120b", "model": "gpt-oss:120b"}]})

    monkeypatch.setattr(providers, "ProviderClient", lambda provider, key, model: ProviderClient(provider, key, model, httpx.MockTransport(catalog)))
    with TestClient(app) as client:
        response = client.get("/api/providers/ollama/models")
        assert response.status_code == 200
        assert response.json() == [{"id": "gpt-oss:120b", "name": "gpt-oss:120b"}]
        assert not ProviderStore().get("ollama")["configured"]
        # Even an existing key is unnecessary for public catalog discovery.
        ProviderStore().update("ollama", "gpt-oss:120b", "test-only-private-key")
        assert client.get("/api/providers/ollama/models").status_code == 200
        assert client.get("/api/providers/openrouter/models").status_code == 400
        assert client.get("/api/providers/unknown/models").status_code == 404
    assert len(requests) == 2
    assert all(str(request.url) == "https://ollama.com/api/tags" for request in requests)
    assert all("authorization" not in request.headers for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(401, "API key"), (404, "exact catalog ID"), (429, "limit"), (503, "temporarily unavailable")])
async def test_ollama_errors_explain_failure_without_echoing_keys(status, expected):
    client = ProviderClient("ollama", "test-only-private-key", "gpt-oss:120b-cloud", httpx.MockTransport(lambda request: httpx.Response(status, json={"error": "test-only-private-key"})))
    with pytest.raises(ProviderError, match=expected) as error:
        await client.test()
    assert "test-only-private-key" not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"message": {}}, {"message": "bad"}])
async def test_connection_does_not_claim_success_for_malformed_response(payload):
    client = ProviderClient("ollama", "test-key", "model", httpx.MockTransport(lambda request: httpx.Response(200, json=payload)))
    with pytest.raises(ProviderError, match="usable test response"):
        await client.test()


@pytest.mark.asyncio
async def test_connection_accepts_thinking_response_at_small_token_limit():
    client = ProviderClient("ollama", "test-key", "model", httpx.MockTransport(lambda request: httpx.Response(200, json={"message": {"role": "assistant", "content": "", "thinking": "thinking"}})))
    assert "Connected" in await client.test()
