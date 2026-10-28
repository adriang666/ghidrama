import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  ArrowDownToLine,
  Check,
  ChevronDown,
  Code2,
  ExternalLink,
  History,
  LoaderCircle,
  PanelRightClose,
  Plus,
  Settings2,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  WandSparkles,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import { errorMessage, formatTime, providerName, request } from "./api";
import type { Evidence, FunctionDetail, Provider, RequestedPrompt, Run, Sample } from "./types";
import { Modal, Notice, Spinner } from "./ui";

type Props = {
  sample?: Sample;
  func: FunctionDetail | null;
  providers: Provider[];
  requestedPrompt: RequestedPrompt | null;
  onSettings: () => void;
  onNavigate: (address: string) => void;
  onClose: () => void;
};

export default function AgentPanel({
  sample,
  func,
  providers,
  requestedPrompt,
  onSettings,
  onNavigate,
  onClose,
}: Props) {
  const [provider, setProvider] = useState("ollama");
  const [model, setModel] = useState("");
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<"investigation" | "pseudocode">("investigation");
  const [budget, setBudget] = useState<"standard" | "extended" | "deep">("extended");
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showActivity, setShowActivity] = useState(false);
  const [includeFunction, setIncludeFunction] = useState(true);
  const [openEvidence, setOpenEvidence] = useState<Evidence | null>(null);
  const [evidencePayload, setEvidencePayload] = useState<unknown>(null);
  const [evidenceError, setEvidenceError] = useState("");
  const textarea = useRef<HTMLTextAreaElement>(null);
  const selectedProvider = providers.find((item) => item.id === provider);
  const selectedRun = runs.find((item) => item.id === runId);
  const running =
    selectedRun?.status === "queued" || selectedRun?.status === "running";
  const ready = sample?.status === "ready" || sample?.status === "partial";

  useEffect(() => {
    const configured = providers.find((item) => item.configured);
    if (!selectedProvider?.configured && configured) setProvider(configured.id);
  }, [providers, selectedProvider?.configured]);
  useEffect(() => {
    setModel(selectedProvider?.model || "");
  }, [provider, selectedProvider?.model]);
  useEffect(() => {
    setRuns([]);
    setRunId(null);
    setError("");
    setQuestion("");
    setMode("investigation");
    setIncludeFunction(true);
    if (!sample?.id) return;
    let cancelled = false;
    const load = async () => {
      try {
        const items = await request<Run[]>(`/api/samples/${sample.id}/runs`);
        if (!cancelled)
          setRuns(
            items.sort((a, b) => b.created_at.localeCompare(a.created_at)),
          );
      } catch (err) {
        if (!cancelled) setError(errorMessage(err));
      }
    };
    void load();
    const interval = window.setInterval(load, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [sample?.id]);

  useEffect(() => {
    if (requestedPrompt && requestedPrompt.sampleId === sample?.id) {
      setQuestion(requestedPrompt.text);
      setMode(requestedPrompt.mode);
      setIncludeFunction(requestedPrompt.scope === "function");
      setRunId(null);
      setError("");
      textarea.current?.focus();
    }
  }, [requestedPrompt, sample?.id]);

  const start = async () => {
    if (!sample || !question.trim() || !ready || busy || running) return;
    setBusy(true);
    setError("");
    try {
      const run = await request<Run>(`/api/samples/${sample.id}/runs`, {
        method: "POST",
        body: JSON.stringify({
          question: question.trim(),
          provider,
          model: model.trim(),
          mode,
          budget,
          expected_revision: sample.analysis_revision,
          ...(func && includeFunction
            ? { function_address: func.address }
            : {}),
        }),
      });
      setRuns((previous) => [run, ...previous]);
      setRunId(run.id);
      setQuestion("");
      setShowActivity(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const cancel = async () => {
    if (!selectedRun) return;
    try {
      const run = await request<Run>(`/api/runs/${selectedRun.id}/cancel`, {
        method: "POST",
      });
      setRuns((previous) =>
        previous.map((item) => (item.id === run.id ? run : item)),
      );
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  const selectEvidence = async (evidence: Evidence) => {
    if (!selectedRun) return;
    setOpenEvidence(evidence);
    setEvidencePayload(null);
    setEvidenceError("");
    try {
      setEvidencePayload(
        await request(`/api/runs/${selectedRun.id}/evidence/${evidence.id}`),
      );
    } catch (err) {
      setEvidenceError(errorMessage(err));
    }
  };

  return (
    <aside className="agent-panel" aria-label="Investigation agent">
      <header className="panel-heading">
        <div>
          <WandSparkles size={16} className="accent" />
          <h2>Investigator</h2>
          <span className="agent-label">MCP</span>
        </div>
        <div>
          <button
            className="icon-button"
            title="New investigation"
            aria-label="New investigation"
            onClick={() => {
              setRunId(null);
              setQuestion("");
              setMode("investigation");
              setError("");
              textarea.current?.focus();
            }}
          >
            <Plus size={16} />
          </button>
          <button
            className="icon-button"
            title="Hide investigator"
            aria-label="Hide investigator"
            onClick={onClose}
          >
            <PanelRightClose size={16} />
          </button>
        </div>
      </header>
      <div className="model-controls">
        <div className="provider-select">
          <Sparkles size={13} />
          <select
            aria-label="Model provider"
            value={provider}
            onChange={(event) => setProvider(event.target.value)}
          >
            {["ollama", "openrouter"].map((id) => (
              <option key={id} value={id}>
                {providerName(id)}
                {providers.find((item) => item.id === id)?.configured
                  ? ""
                  : " · not connected"}
              </option>
            ))}
          </select>
          <ChevronDown size={12} />
        </div>
        <button
          className="icon-button"
          title="Configure model connections"
          aria-label="Configure model connections"
          onClick={onSettings}
        >
          <Settings2 size={15} />
        </button>
      </div>
      {!!runs.length && (
        <div className="run-history">
          <History size={13} />
          <select
            aria-label="Investigation history"
            value={runId || ""}
            onChange={(event) => setRunId(event.target.value || null)}
          >
            <option value="">New investigation</option>
            {runs.map((run) => (
              <option key={run.id} value={run.id}>
                {formatTime(run.created_at)} · {run.mode === "pseudocode" ? "Pseudocode · " : ""}{run.question.slice(0, 65)}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="agent-body scroll-region">
        {error && <Notice>{error}</Notice>}
        {!selectedRun ? (
          <div className="agent-welcome">
            <div className="agent-symbol">
              <WandSparkles size={25} strokeWidth={1.4} />
            </div>
            <h3>Follow the evidence.</h3>
            <p>
              Ask a question. Your agent inspects the program through Ghidra
              tools and connects its findings to source evidence.
            </p>
            <div className="suggested-questions">
              <span className="eyebrow">START AN INVESTIGATION</span>
              {[
                {
                  label: "Understand this program",
                  text: "Give me an overview of this executable and its likely purpose. Distinguish observed facts from inference and cite the evidence.",
                },
                {
                  label: "Explain the selected function",
                  text: func
                    ? `Explain ${func.name} at ${func.address}, its callers, and important side effects. Cite the evidence.`
                    : "Explain the entry point and its important callees. Cite the evidence.",
                },
                {
                  label: "Trace interesting behavior",
                  text: "Inspect imports and strings for file, registry, and network behavior. Follow relevant cross-references and cite the evidence.",
                },
              ].map((item) => (
                <button
                  key={item.label}
                  onClick={() => {
                    setQuestion(item.text);
                    textarea.current?.focus();
                  }}
                >
                  {item.label}
                  <ArrowRight size={14} />
                </button>
              ))}
            </div>
            <div className="agent-principles">
              <ShieldCheck size={15} />
              <span>
                Read-only investigations.
                <br />
                Every conclusion should have evidence.
              </span>
            </div>
          </div>
        ) : (
          <div className="conversation">
            <div className="user-question">
              <span className="message-label">
                YOU<span>{formatTime(selectedRun.created_at)}</span>
              </span>
              <p>{selectedRun.question}</p>
            </div>
            <div className="agent-response">
              <div className="agent-message-heading">
                <div className="mini-agent">
                  <WandSparkles size={13} />
                </div>
                <strong>{selectedRun.answer_kind === "evidence_index" ? "Captured evidence" : selectedRun.mode === "pseudocode" ? "Pseudocode rewrite" : "Investigator"}</strong>
                <span>
                  {running ? (
                    <>
                      <LoaderCircle size={12} className="spin" />
                      Working
                    </>
                  ) : selectedRun.status === "complete" ? (
                    <>
                      <Check size={12} />
                      Complete
                    </>
                  ) : (
                    selectedRun.status
                  )}
                </span>
              </div>
              {selectedRun.usage && <div className="run-budget-meter">
                <span>{(selectedRun.usage.input_tokens + selectedRun.usage.output_tokens).toLocaleString()} / {(selectedRun.limits?.total_tokens || 80000).toLocaleString()} cumulative tokens</span>
                <progress aria-label="Investigation token usage" max={selectedRun.limits?.total_tokens || 80000}
                  value={Math.min(selectedRun.usage.input_tokens + selectedRun.usage.output_tokens, selectedRun.limits?.total_tokens || 80000)} />
              </div>}
              {selectedRun.limit_reason && <Notice tone="warning">{selectedRun.limit_reason}</Notice>}
              {selectedRun.mode === "pseudocode" && selectedRun.answer_kind !== "evidence_index" && <div className="rewrite-note">
                <strong>AI interpretation · revision {selectedRun.analysis_revision}</strong>
                {selectedRun.pseudocode_coverage && <p>
                  {selectedRun.pseudocode_coverage.scope === "program_sketch" ? "Program sketch" : "Function rewrite"} · Ghidra code retrieved for {selectedRun.pseudocode_coverage.addresses.length} of {selectedRun.pseudocode_coverage.total_functions} indexed functions.
                  {selectedRun.pseudocode_coverage.truncated ? " Some source evidence was truncated." : ""}
                </p>}
                <p>Compare the rewrite with its captured Ghidra evidence; inferred names and types may be incorrect.</p>
              </div>}
              {selectedRun.analysis_revision && selectedRun.analysis_revision !== sample?.analysis_revision && <Notice tone="warning">This run uses an earlier analysis revision. Its captured evidence is preserved.</Notice>}
              {!!selectedRun.events?.length && (
                <div className="activity">
                  <button
                    className="activity-toggle"
                    onClick={() => setShowActivity((value) => !value)}
                  >
                    <Terminal size={13} />
                    <span>
                      {
                        selectedRun.events.filter((event) => !!event.tool)
                          .length
                      }{" "}
                      tool actions
                    </span>
                    <ChevronDown
                      size={13}
                      className={showActivity ? "rotated" : ""}
                    />
                  </button>
                  {showActivity && (
                    <ol>
                      {selectedRun.events.map((event, index) => (
                        <li key={index}>
                          <span
                            className={`event-dot ${event.type === "error" ? "event-error" : ""}`}
                          />
                          <div>
                            {event.tool && <code>{event.tool}</code>}
                            <span>{event.message}</span>
                            {event.evidence_id && (
                              <span className="event-evidence">
                                {event.evidence_id}
                              </span>
                            )}
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}
                </div>
              )}
              {selectedRun.answer && (
                <div className="answer-markdown">
                  <ReactMarkdown
                    components={{
                      img: ({ alt }) => (
                        <span className="muted">
                          [Image omitted{alt ? `: ${alt}` : ""}]
                        </span>
                      ),
                      a: ({ href, children }) => {
                        if (href?.startsWith("#evidence-")) {
                          const evidence = selectedRun.evidence?.find(
                            (item) => item.id === href.slice(10),
                          );
                          return (
                            <button
                              className="citation"
                              disabled={!evidence}
                              onClick={() =>
                                evidence && void selectEvidence(evidence)
                              }
                              title={evidence?.summary || "Evidence reference"}
                            >
                              {children}
                            </button>
                          );
                        }
                        return (
                          <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {children}
                            <ExternalLink size={10} />
                          </a>
                        );
                      },
                    }}
                  >
                    {selectedRun.answer.replace(
                      /\[(E\d+)\](?!\()/g,
                      "[$1](#evidence-$1)",
                    )}
                  </ReactMarkdown>
                </div>
              )}
              {selectedRun.error && <Notice>{selectedRun.error}</Notice>}
              {(selectedRun.status === "complete" || selectedRun.status === "partial") && <a className="button secondary small run-download" href={`/api/runs/${selectedRun.id}/download`} download>
                <ArrowDownToLine size={14} />Download answer and evidence
              </a>}
              {(selectedRun.status === "failed" || selectedRun.status === "partial") && <button className="text-button run-download" onClick={() => {
                setQuestion(selectedRun.question);
                setMode(selectedRun.mode || "investigation");
                setRunId(null);
                setError("");
                textarea.current?.focus();
              }}>Use question again</button>}
              {running && !selectedRun.answer && (
                <div className="agent-thinking">
                  <span />
                  <span />
                  <span />
                  <span className="sr-only">Investigation in progress</span>
                </div>
              )}
              {selectedRun.status === "cancelled" && (
                <p className="cancelled-message">
                  Investigation stopped. Evidence gathered so far is preserved.
                </p>
              )}
              {!!selectedRun.evidence?.length && (
                <div className="evidence-list">
                  <span className="eyebrow">SUPPORTING EVIDENCE</span>
                  {selectedRun.evidence.map((evidence) => (
                    <button
                      key={evidence.id}
                      onClick={() => void selectEvidence(evidence)}
                      title={evidence.summary}
                    >
                      <span className="evidence-id">{evidence.id}</span>
                      <span>
                        <strong>{evidence.address || evidence.tool}</strong>
                        <small>{evidence.summary || evidence.tool}</small>
                      </span>
                      <ArrowRight size={12} />
                    </button>
                  ))}
                </div>
              )}
              {selectedRun.usage &&
              (selectedRun.usage.input_tokens ||
                selectedRun.usage.output_tokens) ? (
                <div className="usage-note">
                  {(
                    selectedRun.usage.input_tokens +
                    selectedRun.usage.output_tokens
                  ).toLocaleString()}{" "}
                  tokens<span>·</span>
                  {selectedRun.model}
                </div>
              ) : null}
            </div>
          </div>
        )}
      </div>
      <div className="composer-area">
        {!selectedProvider?.configured && (
          <button className="connect-notice" onClick={onSettings}>
            <Settings2 size={14} />
            <span>Connect a model to start investigating</span>
            <ArrowRight size={13} />
          </button>
        )}
        <div className="composer">
          <label className="task-mode">
            <span>Run budget</span>
            <select aria-label="Investigation budget" value={budget} disabled={running || busy} onChange={event => setBudget(event.target.value as typeof budget)}>
              <option value="standard">Standard · 80k tokens</option>
              <option value="extended">Extended · 250k tokens</option>
              <option value="deep">Deep · 500k tokens</option>
            </select>
          </label>
          <label className="task-mode">
            <span>Task</span>
            <select aria-label="Investigation task" value={mode} onChange={event => setMode(event.target.value as typeof mode)}>
              <option value="investigation">Analyze evidence</option>
              <option value="pseudocode">Rewrite pseudocode</option>
            </select>
          </label>
          {func && (
            <label className="function-context">
              <input
                type="checkbox"
                checked={includeFunction}
                onChange={(event) => setIncludeFunction(event.target.checked)}
              />
              <Code2 size={12} />
              <span>{func.name}</span>
              <code>{func.address}</code>
            </label>
          )}
          <textarea
            ref={textarea}
            aria-label="Investigation question"
            placeholder={
              !sample
                ? "Open an executable to investigate…"
                : !ready
                  ? "Waiting for analysis…"
                  : "Ask about this program…"
            }
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                event.preventDefault();
                void start();
              }
            }}
            rows={3}
          />
          <div className="composer-footer">
            <input
              className="model-name"
              aria-label="Model identifier"
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder="Choose a model in settings"
              spellCheck={false}
            />
            <button
              className={running ? "send-button stop" : "send-button"}
              title={
                running
                  ? "Stop investigation"
                  : "Start investigation (Ctrl+Enter)"
              }
              aria-label={
                running ? "Stop investigation" : "Start investigation"
              }
              disabled={
                !running &&
                (!question.trim() ||
                  !ready ||
                  !selectedProvider?.configured ||
                  !model.trim() ||
                  busy)
              }
              onClick={() => (running ? void cancel() : void start())}
            >
              {running ? (
                <Square size={13} fill="currentColor" />
              ) : busy ? (
                <LoaderCircle size={16} className="spin" />
              ) : (
                <ArrowRight size={18} />
              )}
            </button>
          </div>
        </div>
        <p className="composer-note">
          Analysis excerpts are sent to {providerName(provider)}.
          <br />Budgets count input + output across all calls. Larger budgets may use more provider credits.
        </p>
      </div>
      {openEvidence && (
        <Modal
          title={`Evidence ${openEvidence.id}`}
          subtitle={`${openEvidence.tool}${openEvidence.revision ? ` · analysis revision ${openEvidence.revision}` : ""}`}
          onClose={() => setOpenEvidence(null)}
          className="evidence-modal"
        >
          <div className="modal-body">
            <p className="evidence-summary">{openEvidence.summary}</p>
            <p className="field-help">
              This is the exact tool result captured during the investigation.
              Later analysis changes do not alter this snapshot.
            </p>
            {evidenceError ? (
              <Notice>{evidenceError}</Notice>
            ) : evidencePayload ? (
              <pre className="evidence-payload">
                {JSON.stringify(evidencePayload, null, 2)}
              </pre>
            ) : (
              <Spinner label="Loading captured evidence…" />
            )}
          </div>
          <footer className="modal-footer">
            <button
              className="button secondary"
              onClick={() => setOpenEvidence(null)}
            >
              Close
            </button>
            {openEvidence.address && (
              <button
                className="button primary"
                onClick={() => {
                  onNavigate(openEvidence.address!);
                  setOpenEvidence(null);
                }}
              >
                View current function
                <ArrowRight size={14} />
              </button>
            )}
          </footer>
        </Modal>
      )}
    </aside>
  );
}
