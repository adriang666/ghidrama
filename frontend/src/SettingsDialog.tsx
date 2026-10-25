import { useEffect, useState } from "react";
import {
  Check,
  ChevronRight,
  ExternalLink,
  KeyRound,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import { request, errorMessage, providerName } from "./api";
import type { Provider } from "./types";
import { Modal, Notice } from "./ui";

export default function SettingsDialog({
  providers,
  onClose,
  onChanged,
}: {
  providers: Provider[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const [selected, setSelected] = useState<"ollama" | "openrouter">("ollama");
  const provider = providers.find((item) => item.id === selected);
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(provider?.model || "");
  const [models, setModels] = useState<{ id: string; name: string }[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    setApiKey("");
    setModel(provider?.model || "");
    setModels([]);
    setError("");
    setSuccess("");
  }, [selected, provider?.model]);

  const save = async () => {
    setBusy("save");
    setError("");
    setSuccess("");
    try {
      await request(`/api/providers/${selected}`, {
        method: "PUT",
        body: JSON.stringify({
          model: model.trim(),
          ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
        }),
      });
      setApiKey("");
      setSuccess("Provider settings saved.");
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy("");
    }
  };
  const test = async () => {
    setBusy("test");
    setError("");
    setSuccess("");
    try {
      const result = await request<{ ok: boolean; message: string }>(
        `/api/providers/${selected}/test`,
        { method: "POST" },
      );
      if (!result.ok) setError(result.message);
      else setSuccess(result.message || "Connection verified.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy("");
    }
  };
  const fetchModels = async () => {
    setBusy("models");
    setError("");
    try {
      const items = await request<{ id: string; name: string }[]>(
        `/api/providers/${selected}/models`,
      );
      setModels(items);
      if (!items.length) setError("No models returned by this provider.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy("");
    }
  };
  const removeKey = async () => {
    setBusy("remove");
    setError("");
    setSuccess("");
    try {
      await request(`/api/providers/${selected}`, {
        method: "PUT",
        body: JSON.stringify({ api_key: "", model: provider?.model || "" }),
      });
      setApiKey("");
      setModels([]);
      setSuccess("Saved API key removed from this server.");
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy("");
    }
  };

  return (
    <Modal
      title="Model connections"
      subtitle="Bring your own key. Choose the model for your investigations."
      onClose={onClose}
      className="settings-modal"
    >
      <div className="provider-tabs">
        {(["ollama", "openrouter"] as const).map((id) => (
          <button
            key={id}
            className={selected === id ? "selected" : ""}
            onClick={() => setSelected(id)}
            disabled={!!busy}
          >
            {providerName(id)}
            <span
              className={`connection-dot ${providers.find((p) => p.id === id)?.configured ? "connected" : ""}`}
            />
          </button>
        ))}
      </div>
      <div className="modal-body">
        <div className="provider-description">
          <div className="provider-emblem">
            {selected === "ollama" ? "O" : <span>↗</span>}
          </div>
          <div>
            <h3>{providerName(selected)}</h3>
            <p>
              {selected === "ollama"
                ? "Connect directly to models hosted on ollama.com."
                : "Access models from multiple providers with one API key."}
            </p>
          </div>
          <a
            className="icon-button"
            href={
              selected === "ollama"
                ? "https://ollama.com/settings/keys"
                : "https://openrouter.ai/settings/keys"
            }
            target="_blank"
            rel="noreferrer"
            title="Open API key settings"
          >
            <ExternalLink size={16} />
          </a>
        </div>
        <label className="field-label" htmlFor="api-key">
          <KeyRound size={14} />
          API key
          {provider?.configured && (
            <span className="label-meta">
              <Check size={12} /> Key saved
            </span>
          )}
        </label>
        <input
          id="api-key"
          name="api-key"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={apiKey}
          onChange={(event) => setApiKey(event.target.value)}
          placeholder={
            provider?.configured
              ? "Leave blank to keep your saved key"
              : "Paste your API key"
          }
        />
        {provider?.configured && (
          <button
            className="text-button remove-key-button"
            onClick={() => void removeKey()}
            disabled={!!busy}
          >
            {busy === "remove" ? "Removing saved key…" : "Remove saved API key"}
          </button>
        )}
        <div className="field-heading">
          <label className="field-label" htmlFor="provider-model">
            Default model
          </label>
          <button
            className="text-button"
            disabled={!!busy || !provider?.configured}
            onClick={fetchModels}
          >
            {busy === "models" ? "Loading…" : "Fetch models"}
            <ChevronRight size={13} />
          </button>
        </div>
        <input
          id="provider-model"
          list="available-models"
          value={model}
          onChange={(event) => setModel(event.target.value)}
          placeholder={
            selected === "ollama"
              ? "Model name from your Ollama catalog"
              : "Provider/model identifier"
          }
          autoComplete="off"
          spellCheck={false}
        />
        <datalist id="available-models">
          {models.map((item) => (
            <option value={item.id} key={item.id}>
              {item.name}
            </option>
          ))}
        </datalist>
        <p className="field-help">
          Save a key first, then fetch the current model catalog. Select a model
          that supports tool calling.
          {selected === "ollama" &&
            " Testing Ollama sends a small model request and uses your provider quota."}
        </p>
        <div className="privacy-note">
          <ShieldCheck size={19} />
          <p>
            Keys are encrypted on this server and never stored in your browser.
            When you start an investigation, selected analysis excerpts are sent
            to the provider you choose.
          </p>
        </div>
        {error && <Notice>{error}</Notice>}
        {success && (
          <div className="success-message" role="status">
            <Check size={16} />
            {success}
          </div>
        )}
      </div>
      <footer className="modal-footer">
        <button
          className="button secondary"
          disabled={
            !!busy ||
            !provider?.configured ||
            (selected === "ollama" && !provider.model)
          }
          onClick={test}
        >
          {busy === "test" && <LoaderCircle size={15} className="spin" />}Test
          saved connection
        </button>
        <button
          className="button primary"
          disabled={!!busy || (!apiKey.trim() && !provider?.configured)}
          onClick={save}
        >
          {busy === "save" && <LoaderCircle size={15} className="spin" />}Save
          connection
        </button>
      </footer>
    </Modal>
  );
}
