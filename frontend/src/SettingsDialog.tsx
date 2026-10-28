import { useState } from "react";
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
  const [savedProviders, setSavedProviders] = useState<
    Partial<Record<Provider["id"], Provider>>
  >({});
  const provider =
    savedProviders[selected] || providers.find((item) => item.id === selected);
  const [apiKey, setApiKey] = useState("");
  const [modelDraft, setModelDraft] = useState<string>();
  const model = modelDraft ?? provider?.model ?? "";
  const [models, setModels] = useState<{ id: string; name: string }[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const hasEdits =
    !!apiKey.trim() || model.trim() !== (provider?.model || "");

  const selectProvider = (id: Provider["id"]) => {
    if (id === selected) return;
    setSelected(id);
    setApiKey("");
    setModelDraft(undefined);
    setModels([]);
    setError("");
    setSuccess("");
  };

  const saveCurrentSettings = async () => {
    const saved = await request<Provider>(`/api/providers/${selected}`, {
      method: "PUT",
      body: JSON.stringify({
        model: model.trim(),
        ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
      }),
    });
    setSavedProviders((current) => ({ ...current, [selected]: saved }));
    setApiKey("");
    setModelDraft(undefined);
    onChanged();
  };

  const save = async () => {
    setBusy("save");
    setError("");
    setSuccess("");
    try {
      await saveCurrentSettings();
      setSuccess("Provider settings saved.");
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
      if (hasEdits || !provider?.configured) await saveCurrentSettings();
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
    setSuccess("");
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
      const saved = await request<Provider>(`/api/providers/${selected}`, {
        method: "PUT",
        body: JSON.stringify({ api_key: "", model: provider?.model || "" }),
      });
      setSavedProviders((current) => ({ ...current, [selected]: saved }));
      setApiKey("");
      if (selected !== "ollama") setModels([]);
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
            onClick={() => selectProvider(id)}
            disabled={!!busy}
          >
            {providerName(id)}
            <span
              className={`connection-dot ${(savedProviders[id] || providers.find((p) => p.id === id))?.configured ? "connected" : ""}`}
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
          disabled={!!busy}
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
            disabled={!!busy || (selected !== "ollama" && !provider?.configured)}
            onClick={fetchModels}
          >
            {busy === "models" ? "Loading…" : "Fetch models"}
            <ChevronRight size={13} />
          </button>
        </div>
        <input
          id="provider-model"
          value={model}
          onChange={(event) => setModelDraft(event.target.value)}
          disabled={!!busy}
          placeholder={
            selected === "ollama"
              ? "Model name from your Ollama catalog"
              : "Provider/model identifier"
          }
          autoComplete="off"
          spellCheck={false}
        />
        {models.length > 0 && (
          <>
            <div className="field-heading">
              <label className="field-label" htmlFor="available-models">
                Available models ({models.length})
              </label>
            </div>
            <select
              id="available-models"
              value={models.some((item) => item.id === model) ? model : ""}
              onChange={(event) => setModelDraft(event.target.value)}
              disabled={!!busy}
              style={{ width: "100%" }}
            >
              <option value="" disabled>
                Select a model
              </option>
              {models.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.name === item.id ? item.id : `${item.name} (${item.id})`}
                </option>
              ))}
            </select>
          </>
        )}
        <p className="field-help">
          {selected === "ollama"
            ? "Fetch the public catalog and select a model that supports tool calling. API model names can differ from Ollama CLI aliases. Testing sends a small model request and uses your provider quota."
            : "Save a key first, then fetch the current model catalog. Select a model that supports tool calling."}
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
            (!apiKey.trim() && !provider?.configured) ||
            (selected === "ollama" && !model.trim())
          }
          onClick={test}
        >
          {busy === "test" && <LoaderCircle size={15} className="spin" />}
          {hasEdits ? "Save & test" : "Test connection"}
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
