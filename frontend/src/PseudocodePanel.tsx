import { useEffect, useState } from "react";
import { ArrowDownToLine, Code2, LoaderCircle, Square, WandSparkles } from "lucide-react";
import { errorMessage, request } from "./api";
import type { Analysis, Ask, FunctionDetail, PseudocodeJob, Sample } from "./types";
import { CodeView, Empty, Notice, Spinner } from "./ui";

type Props = {
  sample: Sample;
  analysis: Analysis;
  func: FunctionDetail | null;
  loading: boolean;
  onSelect: (address: string) => void;
  onAsk: Ask;
};

export default function PseudocodePanel({ sample, analysis, func, loading, onSelect, onAsk }: Props) {
  const [job, setJob] = useState<PseudocodeJob | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const active = job?.status === "queued" || job?.status === "running";
  const stale = job && job.analysis_revision !== sample.analysis_revision;
  const base = `/api/samples/${sample.id}/pseudocode`;
  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const result = await request<PseudocodeJob | null>(base);
        if (!disposed) setJob(result);
      } catch (err) {
        if (!disposed) setError(errorMessage(err));
      }
    };
    void load();
    const interval = window.setInterval(load, 2000);
    return () => { disposed = true; window.clearInterval(interval); };
  }, [base]);

  const extract = async (cancel = false) => {
    setBusy(true);
    setError("");
    try {
      setJob(await request<PseudocodeJob>(base + (cancel ? "/cancel" : ""), {
        method: "POST",
        body: JSON.stringify(cancel ? {} : { expected_revision: sample.analysis_revision }),
      }));
    } catch (err) { setError(errorMessage(err)); }
    finally { setBusy(false); }
  };

  return <div className="pseudocode-view scroll-region">
    <div className="pseudocode-intro">
      <span className="eyebrow">PSEUDOCODE WORKSPACE</span>
      <h2>From binary to readable logic</h2>
      <p>Inspect Ghidra’s C-like reconstruction, export all indexed functions, or ask your cloud model to rewrite and explain the logic.</p>
    </div>
    {error && <Notice>{error}</Notice>}
    <section className="pseudocode-export" aria-label="Pseudocode extraction">
      <div>
        <h3>Extract the program</h3>
        <p>{job ? `${job.recovered} of ${job.total} indexed functions recovered · ${job.status}` : `${sample.function_count} indexed functions · extraction runs locally`}</p>
        {job && <>
          <progress value={job.processed} max={Math.max(1, job.total)} aria-label="Pseudocode extraction progress" />
          <small>{job.processed} processed · {job.failed} unavailable · {job.truncated} truncated · revision {job.analysis_revision}</small>
        </>}
      </div>
      <div className="pseudocode-actions">
        {active ? <button className="button secondary small" disabled={busy} onClick={() => void extract(true)}><Square size={13} />Cancel extraction</button>
          : <button className="button primary small" disabled={busy || !sample.function_count} onClick={() => void extract()}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <Code2 size={14} />}{job ? "Extract again" : "Extract all functions"}
          </button>}
        {!!job?.processed && <a className="button secondary small" href={`${base}/download?revision=${job.analysis_revision}`} download><ArrowDownToLine size={14} />Download pseudocode (.c)</a>}
      </div>
    </section>
    {job?.error && <Notice tone="warning">{job.error}</Notice>}
    {stale && <Notice tone="warning">This export belongs to revision {job.analysis_revision}. Extract again for the current analysis. The function below shows the current revision.</Notice>}
    {job?.source_partial && <Notice tone="warning">Ghidra’s analysis was partial. The export covers indexed functions and may omit undiscovered code.</Notice>}
    {!!job?.failed && <details className="pseudocode-failures"><summary>Functions without pseudocode ({job.failed})</summary>
      {job.functions.filter(item => !item.available).map(item => <p key={item.address}><code>{item.address}</code> {item.name}: {item.error || "No decompiler output"}</p>)}
    </details>}
    <section className="pseudocode-cloud" aria-label="Cloud pseudocode actions">
      <div><WandSparkles size={18} /><h3>Rewrite with a cloud model</h3></div>
      <p>Choose Ollama Cloud or OpenRouter in the Investigator, review the request, then send it. The model receives decompiled evidence. Its rewrite is an interpretation that you can compare with Ghidra’s output.</p>
      <div className="pseudocode-actions">
        <button className="button secondary small" disabled={loading || !func?.decompiled} onClick={() => func && onAsk(
          `Rewrite ${func.name} at ${func.address} into clear, readable pseudocode. Preserve behavior and side effects; explain inferred names and uncertainties. Cite the Ghidra evidence.`, "pseudocode", "function")}>Rewrite selected function</button>
        <button className="button secondary small" disabled={!sample.function_count} onClick={() => onAsk(
          "Create a readable pseudocode sketch of this executable's main logic. Inspect the entry point and relevant callees, explain the flow and side effects, and state which functions were examined and what remains unknown. Cite the Ghidra decompilation evidence.", "pseudocode", "program")}>Create program sketch</button>
        <button className="text-button" disabled={loading || !func?.decompiled} onClick={() => func && onAsk(
          `Analyze the Ghidra pseudocode for ${func.name} at ${func.address}. Explain its inputs, outputs, control flow and side effects, distinguishing observations from inferences. Cite the evidence.`, "investigation", "function")}>Analyze selected pseudocode</button>
      </div>
      <small>A program sketch covers the functions the model inspects, within the investigation limits. It is not a full source-code reconstruction.</small>
    </section>
    <div className="pseudocode-function-picker">
      <label htmlFor="pseudocode-function">Ghidra pseudocode</label>
      <select id="pseudocode-function" value={func?.address || ""} onChange={event => onSelect(event.target.value)}>
        {!func && <option value="">{loading ? "Loading function…" : "Choose a function"}</option>}
        {(analysis.functions || []).map(item => <option key={item.address} value={item.address}>{item.name} · {item.address}</option>)}
      </select>
    </div>
    {loading ? <Spinner label="Decompiling function…" /> : func?.decompiled ? <div className="pseudocode-source">
      <div className="code-banner"><Code2 size={14} /><span>Ghidra output · {func.address}</span><span className="code-banner-note">Reconstructed C · verify against assembly</span></div>
      {func.decompiled_truncated && <Notice tone="warning">This function exceeded the decompiler output limit. Its pseudocode is incomplete.</Notice>}
      <CodeView code={func.decompiled} />
    </div> : <Empty title="No pseudocode available"><p>{func?.decompile_error || "Select a function with decompiler output. Unrecovered functions can still be inspected in Assembly."}</p></Empty>}
  </div>;
}
