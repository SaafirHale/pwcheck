"use client";

import { useCallback, useEffect, useState } from "react";
import { BITS_PER_WORD, MAX_WORDS, MIN_WORDS, WORDLIST_SIZE, generatePassphrase, type Passphrase } from "../core/passphrase.js";
import { CopyButton, Switch, formatCount } from "./ui.js";

const SEPARATORS: { value: string; label: string }[] = [
  { value: "-", label: "hyphen" },
  { value: " ", label: "space" },
  { value: ".", label: "period" },
  { value: "_", label: "underscore" },
];

export type PassphraseGeneratorProps = {
  /** Called with the passphrase when "Check this one" is pressed. Omit to hide the button. */
  onUse?: (passphrase: string) => void;
};

export function PassphraseGenerator({ onUse }: PassphraseGeneratorProps) {
  const [words, setWords] = useState(6);
  const [separator, setSeparator] = useState("-");
  const [capitalize, setCapitalize] = useState(false);
  const [digit, setDigit] = useState(false);
  const [current, setCurrent] = useState<Passphrase | null>(null);

  const generate = useCallback(() => {
    setCurrent(generatePassphrase({ words, separator, capitalize, digit }));
  }, [words, separator, capitalize, digit]);

  // Generated on the client only, so a statically rendered page never ships a passphrase in its HTML.
  useEffect(() => {
    generate();
  }, [generate]);

  return (
    <div className="pw-gen">
      <div className="pw-gen-out" aria-live="polite">
        <output className="pw-gen-phrase" htmlFor="pw-gen-words">
          {current?.passphrase ?? " "}
        </output>
        <div className="pw-gen-bits">
          <span className="pw-stat">{current ? current.entropyBits.toFixed(1) : "—"}</span>
          <span className="pw-muted"> bits of entropy</span>
        </div>
      </div>

      <div className="pw-actions">
        <button type="button" className="pw-btn" onClick={generate}>
          Generate another
        </button>
        {current ? <CopyButton text={current.passphrase} /> : null}
        {onUse && current ? (
          <button type="button" className="pw-mini" onClick={() => onUse(current.passphrase)}>
            Check this one
          </button>
        ) : null}
      </div>

      <div className="pw-gen-controls">
        <label className="pw-field">
          <span className="pw-field-label">Words</span>
          <span className="pw-stepper">
            <button type="button" className="pw-mini" aria-label="Fewer words" disabled={words <= MIN_WORDS} onClick={() => setWords((w) => w - 1)}>
              −
            </button>
            <input
              id="pw-gen-words"
              type="number"
              min={MIN_WORDS}
              max={MAX_WORDS}
              value={words}
              autoComplete="off"
              onChange={(e) => {
                const n = Math.round(Number(e.target.value));
                if (n >= MIN_WORDS && n <= MAX_WORDS) setWords(n);
              }}
            />
            <button type="button" className="pw-mini" aria-label="More words" disabled={words >= MAX_WORDS} onClick={() => setWords((w) => w + 1)}>
              +
            </button>
          </span>
        </label>
        <label className="pw-field">
          <span className="pw-field-label">Separator</span>
          <select value={separator} onChange={(e) => setSeparator(e.target.value)} autoComplete="off">
            {SEPARATORS.map((s) => (
              <option key={s.label} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <Switch on={capitalize} onChange={setCapitalize}>
          Capitalise words
        </Switch>
        <Switch on={digit} onChange={setDigit}>
          Add a digit
        </Switch>
      </div>

      <p className="pw-note">
        Each word is drawn uniformly from the {formatCount(WORDLIST_SIZE)} words of the EFF Large Wordlist using{" "}
        <code>crypto.getRandomValues</code>, with rejection sampling so no word is favoured. That is {BITS_PER_WORD.toFixed(2)} bits
        per word, plus {Math.log2(10).toFixed(2)} for the optional digit. Separator and capitals add nothing: the figure assumes the
        attacker knows the wordlist and every setting, so it is a floor, not a guess. The passphrase exists only in this page until you
        copy it; anything copied stays on your clipboard until something replaces it.
      </p>
      <p className="pw-note pw-muted">
        Wordlist:{" "}
        <a className="pw-link" href="https://www.eff.org/dice" target="_blank" rel="noreferrer noopener">
          EFF Large Wordlist
        </a>{" "}
        by the Electronic Frontier Foundation, used under{" "}
        <a className="pw-link" href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer noopener">
          CC BY 4.0
        </a>
        . Dice numbers removed; words and order unchanged.
      </p>
    </div>
  );
}
