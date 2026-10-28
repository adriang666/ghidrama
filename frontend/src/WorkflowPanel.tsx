import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import { ArrowDownToLine, LoaderCircle, Square, WandSparkles } from "lucide-react";
import { errorMessage, request } from "./api";
import type { Provider, Run, Sample, WorkflowJob } from "./types";
import { Notice } from "./ui";

export default function WorkflowPanel({ sample, providers, onSettings }: { sample: Sample; providers: Provider[]; onSettings: () => void }) {
  const configured = providers.filter(item => item.configured && item.model);
  const [choice, setChoice] = useState("");
  const provider = configured.find(item => item.id === choice) || configured[0];
  const [job, setJob] = useState<WorkflowJob | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [limit, setLimit] = useState(5);
  const [runs, setRuns] = useState<Run[]>([]);
  const base = `/api/samples/${sample.id}/workflow`;
  const active = job?.status === "queued" || job?.status === "running";
  useEffect(() => {
    let disposed = false;
    let polling = false;
    const load = async () => {
      if (polling) return;
      polling = true;
      try {
        const latest = await request<WorkflowJob | null>(base);
        const answers = latest ? await Promise.all(latest.run_ids.map(id => request<Run>(`/api/runs/${id}`))) : [];
        if (!disposed) { setJob(latest); setRuns(answers); }
      } catch (err) { if (!disposed) setError(errorMessage(err)); }
      finally { polling = false; }
    };
    void load();
    const interval = window.setInterval(load, 2500);
    return () => { disposed = true; window.clearInterval(interval); };
  }, [base]);

  const start = async (cancel = false) => {
    setBusy(true); setError("");
    try {
      setJob(await request<WorkflowJob>(base + (cancel ? "/cancel" : ""), {
        method: "POST", body: JSON.stringify(cancel ? {} : { provider: provider?.id, function_limit: limit, expected_revision: sample.analysis_revision }),
      }));
      if (!cancel) setRuns([]);
    } catch (err) { setError(errorMessage(err)); }
    finally { setBusy(false); }
  };

  return <div className="workflow-view scroll-region">
    <span className="eyebrow">ONE-CLICK WORKFLOW</span>
    <h2>Unpack. Understand. Rewrite.</h2>
    <p>Unpack detected UPX files, analyze with Ghidra, then use your cloud model to identify and rewrite the main application routines.</p>
    {error && <Notice>{error}</Notice>}
    <section className="workflow-controls">
      {provider ? <>
        <label>Cloud model<select aria-label="Workflow cloud model" value={provider.id} disabled={active || busy} onChange={event => setChoice(event.target.value)}>
          {configured.map(item => <option key={item.id} value={item.id}>{item.id === "ollama" ? "Ollama Cloud" : "OpenRouter"} · {item.model}</option>)}
        </select></label>
        <label>Main functions<select aria-label="Maximum main functions" value={limit} disabled={active || busy} onChange={event => setLimit(Number(event.target.value))}>
          {[1, 3, 5].map(n => <option key={n} value={n}>Up to {n}</option>)}
        </select></label>
      </> : <p>Configure a cloud model to begin. <button className="text-button" onClick={onSettings}>Open provider settings</button></p>}
      {active ? <button className="button secondary" disabled={busy} onClick={() => void start(true)}><Square size={14} />Cancel workflow</button>
        : <button className="button primary" disabled={busy || !provider} onClick={() => void start()}>
          {busy ? <LoaderCircle size={15} className="spin" /> : <WandSparkles size={15} />}Unpack, analyze & rewrite</button>}
      <small>Starting sends decompiled code and analysis evidence to the selected provider. Cloud usage may incur charges. One discovery pass and one request per selected function; a shared 500,000-token budget uses estimates and reported usage. Completed results are retained.</small>
    </section>
    {job && <section className="workflow-results" aria-live="polite">
      <div className="workflow-status"><strong>{job.status} · {job.stage}</strong>
        {active && <LoaderCircle size={16} className="spin" />}
        {!!job.run_ids.length && <a className="button secondary small" href={`/api/workflows/${job.id}/download`} download><ArrowDownToLine size={14} />Download results & evidence</a>}
      </div>
      <progress aria-label="Workflow rewrite progress" max={Math.max(1, job.functions.length)} value={job.functions.filter(f => ["complete", "failed", "cancelled"].includes(f.status)).length} />
      <p className="muted">{job.provider} / {job.model} · revision {job.analysis_revision || "pending"} · {job.tokens_reported.toLocaleString()} tokens reported · {job.budget_used.toLocaleString()} / {job.token_limit.toLocaleString()} budget reserved</p>
      {job.error && <Notice tone="warning">{job.error}</Notice>}
      {job.analysis_revision > 0 && job.analysis_revision !== sample.analysis_revision && !active && <Notice tone="warning">These results belong to an earlier analysis revision.</Notice>}
      <p>AI interpretations with inferred names. Function selection is bounded and may miss important routines. Compare the rewrites with their Ghidra evidence; semantic equivalence is not verified.</p>
      {job.functions.map(item => <div className="workflow-function" key={item.address}>
        <strong>{item.name} · <code>{item.address}</code> · {item.status}</strong><p>{item.reason}</p>
        {item.error && <Notice tone="warning">{item.error}</Notice>}
      </div>)}
      {runs.map(run => <details className="workflow-answer" key={run.id}>
        <summary>{run.id === job.discovery_id ? "Main-function discovery" : `Rewrite ${run.function_address}`} · {run.status}</summary>
        {run.error && <Notice tone="warning">{run.error}</Notice>}
        <div className="markdown-answer"><ReactMarkdown>{run.answer || "Gathering evidence…"}</ReactMarkdown></div>
        <div className="pseudocode-actions">{run.evidence.map(e => <a key={e.id} href={`/api/runs/${run.id}/evidence/${e.id}`} target="_blank" rel="noreferrer">[{e.id}] {e.summary}</a>)}</div>
      </details>)}
    </section>}
  </div>;
}
