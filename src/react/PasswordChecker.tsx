"use client";

import { useDeferredValue, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { checkPwned, PREFIX_LENGTH, type BreachResult } from "../core/hibp.js";
import { formatRate, loadStrengthEstimator, type StrengthEstimator, type StrengthReport, type Weakness } from "../core/strength.js";
import { PassphraseGenerator } from "./PassphraseGenerator.js";
import { Section, Switch, formatCount } from "./ui.js";

export type PasswordCheckerProps = {
  /**
   * Words tied to the page or the person, scored as guessable (zxcvbn "user inputs").
   * Site names and usernames belong here.
   */
  userInputs?: string[];
  /** Start with the breach check on (default) or off. */
  defaultBreachCheck?: boolean;
  /** Show the passphrase generator section. Default true. */
  generator?: boolean;
  /** Override the range endpoint (tests, self-hosted mirrors). */
  endpoint?: string;
  className?: string;
};

type Breach =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "done"; result: BreachResult }
  | { kind: "error"; message: string };

const HOST = "api.pwnedpasswords.com";

export function PasswordChecker({ userInputs, defaultBreachCheck = true, generator = true, endpoint, className }: PasswordCheckerProps) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [breachOn, setBreachOn] = useState(defaultBreachCheck);
  const [breach, setBreach] = useState<Breach>({ kind: "idle" });
  const [estimator, setEstimator] = useState<StrengthEstimator | null>(null);
  const [loadError, setLoadError] = useState(false);
  const inflight = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let live = true;
    loadStrengthEstimator().then(
      (e) => live && setEstimator(e),
      () => live && setLoadError(true),
    );
    return () => {
      live = false;
    };
  }, []);

  // A result belongs to one exact password and one setting. Any change drops it and cancels a pending request.
  useEffect(() => {
    inflight.current?.abort();
    inflight.current = null;
    setBreach({ kind: "idle" });
  }, [password, breachOn]);

  useEffect(() => () => inflight.current?.abort(), []);

  const inputsKey = JSON.stringify(userInputs ?? []);
  const deferred = useDeferredValue(password);
  const report = useMemo<StrengthReport | null>(
    () => (estimator && deferred ? estimator.check(deferred, JSON.parse(inputsKey) as string[]) : null),
    [estimator, deferred, inputsKey],
  );

  async function runBreachCheck(e?: FormEvent) {
    e?.preventDefault();
    if (!breachOn || !password) return;
    inflight.current?.abort();
    const ac = new AbortController();
    inflight.current = ac;
    setBreach({ kind: "busy" });
    try {
      const result = await checkPwned(password, { signal: ac.signal, endpoint });
      if (!ac.signal.aborted) setBreach({ kind: "done", result });
    } catch (err) {
      if (ac.signal.aborted) return;
      setBreach({
        kind: "error",
        message:
          err instanceof TypeError
            ? `Could not reach ${HOST}. The strength results are unaffected.`
            : `The breach check failed (${err instanceof Error ? err.message : "unknown error"}). The strength results are unaffected.`,
      });
    } finally {
      if (inflight.current === ac) inflight.current = null;
    }
  }

  function usePassphrase(p: string) {
    setPassword(p);
    inputRef.current?.focus();
    inputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  return (
    <div className={`pw-root${className ? ` ${className}` : ""}`}>
      <Section index={1} label="Password" note="Scored in this tab as you type.">
        <form className="pw-form" autoComplete="off" onSubmit={runBreachCheck} noValidate>
          <label htmlFor="pw-input" className="pw-field-label">
            Password to check
          </label>
          <div className="pw-input-row">
            <input
              ref={inputRef}
              id="pw-input"
              className="pw-input"
              type={visible ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              data-1p-ignore=""
              data-lpignore="true"
              data-bwignore=""
              data-form-type="other"
              placeholder="Type or paste"
            />
            <button type="button" className="pw-mini" aria-pressed={visible} onClick={() => setVisible((v) => !v)}>
              {visible ? "Hide" : "Show"}
            </button>
            <button
              type="button"
              className="pw-mini"
              disabled={!password}
              onClick={() => {
                setPassword("");
                setVisible(false);
                inputRef.current?.focus();
              }}
            >
              Clear
            </button>
          </div>

          <div className="pw-breach-toggle">
            <Switch id="pw-breach-switch" on={breachOn} onChange={setBreachOn}>
              Breach check
            </Switch>
            {breachOn ? (
              <button type="submit" className="pw-btn" disabled={!password || breach.kind === "busy"}>
                {breach.kind === "busy" ? "Checking…" : "Check breaches"}
              </button>
            ) : null}
          </div>

          <p className="pw-privacy" data-mode={breachOn ? "breach" : "offline"}>
            {breachOn ? (
              <>
                Your password never leaves this page. When you press <strong>Check breaches</strong>, the page hashes it with SHA-1 and
                sends only the first {PREFIX_LENGTH} of the hash&rsquo;s 40 hex characters to <code>{HOST}</code>. The other 35 are
                matched here, against the list that comes back.
              </>
            ) : (
              <>
                <strong>Strength only.</strong> The breach check is off, so this checker makes no network requests. Everything below is
                computed in this page.
              </>
            )}
          </p>
        </form>
      </Section>

      <Section index={2} label="Strength" note="zxcvbn-ts with English and common-password dictionaries.">
        {loadError ? (
          <p className="pw-error">The strength dictionaries failed to load. Reload the page to try again.</p>
        ) : !estimator ? (
          <p className="pw-muted">Loading dictionaries…</p>
        ) : !report ? (
          <p className="pw-muted">Enter a password to see how it would be guessed.</p>
        ) : (
          <StrengthView report={report} password={deferred} visible={visible} />
        )}
      </Section>

      <Section index={3} label="Time to crack" note="Estimated guesses ÷ guessing rate, for four kinds of attack.">
        {report ? <CrackTimes report={report} /> : <p className="pw-muted">Waiting for a password.</p>}
      </Section>

      <Section index={4} label="Breaches" note="Have I Been Pwned · Pwned Passwords range API.">
        <BreachView breach={breach} on={breachOn} hasPassword={!!password} />
      </Section>

      {generator ? (
        <Section index={5} label="Passphrase" note="Random words are easier to type and harder to guess.">
          <PassphraseGenerator onUse={usePassphrase} />
        </Section>
      ) : null}

      <Section index={generator ? 6 : 5} label="What leaves this page" note="The threat model, in short.">
        <ul className="pw-facts">
          <li>
            <strong>The password.</strong> Never sent. It lives in this tab&rsquo;s memory while the page is open. This tool does not
            store it, log it or write it to the console. The field sets <code>autocomplete=&quot;off&quot;</code> and the common
            password-manager opt-outs; most honour them, though a browser may still offer to save what you type.
          </li>
          <li>
            <strong>Strength.</strong> Computed entirely in the page. No request is made for it.
          </li>
          <li>
            <strong>Breach check, when on.</strong> One request per press of the button, to <code>{HOST}/range/</code> followed by{" "}
            {PREFIX_LENGTH} hex characters of the password&rsquo;s SHA-1 hash. There are 1,048,576 possible prefixes, and the
            response lists every breached hash that shares yours, padded with fake entries so its size gives nothing away. Like any request, it also carries your IP address and user agent, and its Origin header names this site.
          </li>
          <li>
            <strong>What the prefix still reveals.</strong> Twenty bits of the hash. If the password is in the breach corpus, it is one
            of the entries in that response. If it is not, someone holding the prefix could discard almost every wrong
            guess without testing it. That is why the check runs on a button press rather than as you type: checking every keystroke
            would send a prefix for each short, easily guessed fragment of the password.
          </li>
          <li>
            <strong>No analytics, no storage.</strong> This tool sets no cookies, uses no browser storage and reports nothing
            anywhere.
          </li>
        </ul>
      </Section>
    </div>
  );
}

function StrengthView({ report, password, visible }: { report: StrengthReport; password: string; visible: boolean }) {
  return (
    <div className="pw-strength">
      <div className="pw-score" data-score={report.score}>
        <div className="pw-meter" aria-hidden="true">
          {[0, 1, 2, 3, 4].map((n) => (
            <span key={n} data-on={n <= report.score} />
          ))}
        </div>
        <div className="pw-score-line" aria-live="polite">
          <span className="pw-stat">{report.label}</span>
          <span className="pw-muted">
            {" "}
            · score {report.score} of 4 · about 10<sup>{Math.round(report.guessesLog10)}</sup> guesses · {report.length} characters
          </span>
        </div>
        {report.truncated ? (
          <p className="pw-note pw-muted">Only the first 256 characters were scored. Past that, length alone makes guessing impractical.</p>
        ) : null}
      </div>

      <PatternMap report={report} password={password} visible={visible} />

      {report.weaknesses.length ? (
        <ol className="pw-list">
          {report.weaknesses.map((w, k) => (
            <WeaknessRow key={`${w.i}-${w.kind}`} w={w} n={k + 1} visible={visible} />
          ))}
        </ol>
      ) : (
        <p className="pw-note">
          No dictionary words, keyboard walks, dates, repeats or sequences found. zxcvbn priced every character as random.
        </p>
      )}

      {report.feedback.warning || report.feedback.suggestions.length ? (
        <div className="pw-feedback">
          {report.feedback.warning ? <p className="pw-warn">{report.feedback.warning}</p> : null}
          {report.feedback.suggestions.length ? (
            <ul className="pw-suggest">
              {report.feedback.suggestions.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

/** A bar across the password: each found pattern is a numbered block, random stretches are hairline gaps. */
function PatternMap({ report, password, visible }: { report: StrengthReport; password: string; visible: boolean }) {
  const total = password.length;
  if (!total) return null;
  const blocks: { start: number; len: number; n?: number; kind?: string; text: string }[] = [];
  let at = 0;
  report.weaknesses.forEach((w, k) => {
    if (w.i > at) blocks.push({ start: at, len: w.i - at, text: password.slice(at, w.i) });
    blocks.push({ start: w.i, len: w.length, n: k + 1, kind: w.kind, text: w.revealed.token });
    at = w.j + 1;
  });
  if (at < total) blocks.push({ start: at, len: total - at, text: password.slice(at) });

  return (
    <div className="pw-map" role="img" aria-label={`${report.weaknesses.length} pattern(s) found across ${report.length} characters`}>
      {blocks.map((b) => (
        <div key={b.start} className="pw-map-block" data-kind={b.kind ?? "random"} style={{ flexGrow: b.len }}>
          <span className="pw-map-bar" />
          <span className="pw-map-cap">{b.n ? b.n : visible ? "" : "random"}</span>
          {visible ? <span className="pw-map-text">{b.text}</span> : null}
        </div>
      ))}
    </div>
  );
}

function WeaknessRow({ w, n, visible }: { w: Weakness; n: number; visible: boolean }) {
  return (
    <li className="pw-row">
      <span className="pw-row-n">{n}</span>
      <div className="pw-row-main">
        <div className="pw-row-title">{w.title}</div>
        <div className="pw-row-detail">{w.detail}</div>
        {visible ? (
          <div className="pw-row-reveal">
            <code>{w.revealed.token}</code>
            {w.revealed.note ? <span className="pw-muted"> — {w.revealed.note}</span> : null}
          </div>
        ) : (
          <div className="pw-row-reveal pw-muted">
            Characters {w.i + 1}–{w.j + 1}. Press Show to see which.
          </div>
        )}
      </div>
    </li>
  );
}

function CrackTimes({ report }: { report: StrengthReport }) {
  return (
    <div>
      <ul className="pw-list">
        {report.crackTimes.map((row) => (
          <li key={row.id} className="pw-row pw-crack">
            <div className="pw-row-main">
              <div className="pw-row-title">{row.label}</div>
              <div className="pw-row-detail">
                {row.description} <span className="pw-muted">Assumes {formatRate(row.perSecond)}.</span>
              </div>
            </div>
            <div className="pw-crack-time" data-fast={row.seconds < 86400}>
              {row.display}
            </div>
          </li>
        ))}
      </ul>
      <p className="pw-note pw-muted">
        Rates are zxcvbn-ts&rsquo;s defaults. Read them as orders of magnitude: real speed depends on the hash, the hardware, and how
        much the attacker cares about you in particular.
      </p>
    </div>
  );
}

function BreachView({ breach, on, hasPassword }: { breach: Breach; on: boolean; hasPassword: boolean }) {
  if (!on) {
    return <p className="pw-muted">Off. Turn on Breach check above to look the password up.</p>;
  }
  if (breach.kind === "idle") {
    return (
      <p className="pw-muted">
        {hasPassword ? "Press Check breaches to look this password up." : "Enter a password, then press Check breaches."}
      </p>
    );
  }
  if (breach.kind === "busy") return <p className="pw-muted">Checking…</p>;
  if (breach.kind === "error") return <p className="pw-error">{breach.message}</p>;

  const r = breach.result;
  return (
    <div className="pw-breach" aria-live="polite">
      {r.count > 0 ? (
        <>
          <p className="pw-breach-head" data-found="true">
            <span className="pw-stat">Found {formatCount(r.count)} {r.count === 1 ? "time" : "times"}</span> in breach data.
          </p>
          <p>
            Attackers try known-breached passwords first, whatever their strength score. Do not use this one, and change it anywhere it
            is in use.
          </p>
        </>
      ) : (
        <>
          <p className="pw-breach-head" data-found="false">
            <span className="pw-stat">Not found</span> in Pwned Passwords.
          </p>
          <p>That means this exact password is not in the corpus. It says nothing about whether it is strong; the score above does.</p>
        </>
      )}
      <dl className="pw-sent">
        <dt>Sent</dt>
        <dd>
          <code>GET {r.url}</code> with <code>Add-Padding: true</code>
        </dd>
        <dt>Received</dt>
        <dd>
          {formatCount(r.realEntries + r.paddingEntries)} hash suffixes: {formatCount(r.realEntries)} real,{" "}
          {formatCount(r.paddingEntries)} padding (ignored)
        </dd>
        <dt>Matched</dt>
        <dd>In this page, against the remaining 35 characters of the hash.</dd>
      </dl>
    </div>
  );
}
