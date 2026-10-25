import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { AlertCircle, LoaderCircle, X } from "lucide-react";

export function Status({ value }: { value: string }) {
  return (
    <span className={`status status-${value}`}>
      <span className="status-dot" />
      {value === "ready"
        ? "Analyzed"
        : value[0]?.toUpperCase() + value.slice(1)}
    </span>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading">
      <LoaderCircle size={18} className="spin" />
      <span>{label}</span>
    </div>
  );
}

export function Notice({
  children,
  tone = "error",
}: {
  children: ReactNode;
  tone?: "error" | "warning" | "info";
}) {
  return (
    <div
      className={`notice notice-${tone}`}
      role={tone === "error" ? "alert" : "status"}
    >
      <AlertCircle size={16} />
      <div>{children}</div>
    </div>
  );
}

export function Modal({
  title,
  subtitle,
  children,
  onClose,
  className = "",
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  onClose: () => void;
  className?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog
      ref={ref}
      className={`modal ${className}`}
      onCancel={onClose}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="modal-inner">
        <header className="modal-header">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={19} />
          </button>
        </header>
        {children}
      </div>
    </dialog>
  );
}

export function Empty({
  icon,
  title,
  children,
}: {
  icon?: ReactNode;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-icon">{icon}</div>}
      <h3>{title}</h3>
      <div className="empty-copy">{children}</div>
    </div>
  );
}

export function CodeView({ code }: { code: string }) {
  const lines = code.split("\n");
  return (
    <div className="code-scroll">
      <div
        className="code-content"
        role="region"
        aria-label="Decompiled code"
        tabIndex={0}
      >
        {lines.map((line, index) => (
          <div className="code-line" key={index}>
            <span className="line-number" aria-hidden="true">
              {index + 1}
            </span>
            <code>{highlight(line)}</code>
          </div>
        ))}
      </div>
    </div>
  );
}

function highlight(line: string): ReactNode[] {
  const pattern =
    /(\/\/.*|\/\*.*?\*\/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:void|int|char|short|long|float|double|bool|undefined\d*|uint\d*|ulong|size_t|struct|const|unsigned|signed|return|if|else|while|for|do|switch|case|break|continue|goto|typedef|sizeof|NULL|true|false)\b|\b0x[\da-fA-F]+\b|\b\d+\b)/g;
  const parts: ReactNode[] = [];
  let cursor = 0;
  for (const match of line.matchAll(pattern)) {
    if (match.index! > cursor) parts.push(line.slice(cursor, match.index));
    const text = match[0];
    const kind =
      text.startsWith("//") || text.startsWith("/*")
        ? "comment"
        : text.startsWith('"') || text.startsWith("'")
          ? "string"
          : /^(0x|\d)/.test(text)
            ? "number"
            : "keyword";
    parts.push(
      <span className={`syntax-${kind}`} key={match.index}>
        {text}
      </span>,
    );
    cursor = match.index! + text.length;
  }
  if (cursor < line.length) parts.push(line.slice(cursor));
  return parts.length ? parts : ["\u00a0"];
}
