import { useState, type ReactNode } from "react";

export function Section({ index, label, note, children }: { index: number; label: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section className="pw-sec">
      <div className="pw-split">
        <div className="pw-label">
          <div className="pw-label-idx">{String(index).padStart(2, "0")}</div>
          <h3 className="pw-h3">{label}</h3>
          {note ? <div className="pw-label-note">{note}</div> : null}
        </div>
        <div className="pw-body">{children}</div>
      </div>
    </section>
  );
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label = "Copy", done = "Copied" }: { text: string; label?: string; done?: string }) {
  const [state, setState] = useState<"idle" | "done" | "fail">("idle");
  return (
    <button
      type="button"
      className="pw-mini"
      onClick={async () => {
        setState((await writeClipboard(text)) ? "done" : "fail");
        setTimeout(() => setState("idle"), 1400);
      }}
    >
      {state === "done" ? done : state === "fail" ? "Blocked" : label}
    </button>
  );
}

export function Switch({ on, onChange, children, id }: { on: boolean; onChange: (on: boolean) => void; children: ReactNode; id?: string }) {
  return (
    <button type="button" id={id} role="switch" aria-checked={on} className="pw-switch" data-on={on} onClick={() => onChange(!on)}>
      <span className="pw-switch-box" aria-hidden="true">
        <span className="pw-switch-dot" />
      </span>
      <span>{children}</span>
    </button>
  );
}

export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}
