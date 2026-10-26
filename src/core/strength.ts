// Strength estimation with zxcvbn-ts and its English + common dictionaries.
//
// zxcvbn estimates how many guesses a smart attacker needs: it looks for the
// cheapest way to build the password out of dictionary words, keyboard walks,
// dates, repeats and sequences, and only falls back to brute force for the
// parts it cannot explain. The result below adds plain-language weaknesses and
// crack times under four attack models on top of the library's own feedback.

import type {
  CrackTimes,
  DateMatch,
  DictionaryMatch,
  L33tMatch,
  MatchEstimated,
  RegexMatch,
  RepeatMatch,
  Score,
  SequenceMatch,
  SpatialMatch,
  TimeEstimationValues,
  WordSequenceMatch,
  ZxcvbnFactory,
} from "@zxcvbn-ts/core";

export type AttackModelId = keyof CrackTimes;

export type AttackModel = {
  id: AttackModelId;
  label: string;
  /** Guesses per second assumed by the model. */
  perSecond: number;
  description: string;
};

/**
 * zxcvbn-ts's default rates, passed in explicitly so the copy shown next to a
 * crack time is derived from the same number that produced it.
 */
export const TIME_ESTIMATION_VALUES: TimeEstimationValues = {
  scoring: { 0: 1e3, 1: 1e6, 2: 1e8, 3: 1e10 },
  attackTime: {
    onlineThrottlingXPerHour: 100,
    onlineNoThrottlingXPerSecond: 10,
    offlineSlowHashingXPerSecond: 1e4,
    offlineFastHashingXPerSecond: 1e10,
  },
};

export const ATTACK_MODELS: readonly AttackModel[] = [
  {
    id: "onlineThrottlingXPerHour",
    label: "Online, throttled",
    perSecond: TIME_ESTIMATION_VALUES.attackTime.onlineThrottlingXPerHour / 3600,
    description: "Guessing at a live login that rate-limits or locks the account.",
  },
  {
    id: "onlineNoThrottlingXPerSecond",
    label: "Online, unthrottled",
    perSecond: TIME_ESTIMATION_VALUES.attackTime.onlineNoThrottlingXPerSecond,
    description: "Guessing at a live login with no rate limit.",
  },
  {
    id: "offlineSlowHashingXPerSecond",
    label: "Offline, slow hash",
    perSecond: TIME_ESTIMATION_VALUES.attackTime.offlineSlowHashingXPerSecond,
    description: "A stolen database hashed with bcrypt, scrypt, Argon2 or PBKDF2.",
  },
  {
    id: "offlineFastHashingXPerSecond",
    label: "Offline, fast hash",
    perSecond: TIME_ESTIMATION_VALUES.attackTime.offlineFastHashingXPerSecond,
    description: "A stolen database of unsalted MD5, SHA-1 or NTLM hashes, cracked on GPUs.",
  },
];

/** zxcvbn's own wording for each score, from the comments in its scoring code. */
export const SCORE_LABELS: Record<Score, string> = {
  0: "Too guessable",
  1: "Very guessable",
  2: "Somewhat guessable",
  3: "Safely unguessable",
  4: "Very unguessable",
};

export type WeaknessKind =
  | "common-password"
  | "dictionary-word"
  | "name"
  | "personal"
  | "l33t"
  | "reversed"
  | "keyboard-walk"
  | "repeat"
  | "sequence"
  | "word-sequence"
  | "date"
  | "recent-year";

export type Weakness = {
  kind: WeaknessKind;
  title: string;
  /** Plain-language explanation. Never contains any part of the password. */
  detail: string;
  /** Start and end index (inclusive) of the matched part of the password. */
  i: number;
  j: number;
  /** Characters covered. */
  length: number;
  /** log10 of the guesses zxcvbn assigns to this part alone. */
  guessesLog10: number;
  /**
   * Details derived from the password itself (the matched text, the word it
   * decodes to, its rank). Render only when the password is visible.
   */
  revealed: {
    token: string;
    note?: string;
  };
};

export type CrackTimeRow = AttackModel & {
  seconds: number;
  display: string;
};

export type StrengthReport = {
  score: Score;
  label: string;
  guesses: number;
  guessesLog10: number;
  crackTimes: CrackTimeRow[];
  weaknesses: Weakness[];
  /** Parts of the password zxcvbn could not explain and priced as brute force. */
  bruteforceChars: number;
  feedback: { warning: string | null; suggestions: string[] };
  length: number;
  /** True when the password is longer than the estimator's limit and only a prefix was scored. */
  truncated: boolean;
  calcTimeMs: number;
};

export type StrengthEstimator = {
  check(password: string, userInputs?: (string | number)[]): StrengthReport;
};

export const MAX_LENGTH = 256;

let estimator: Promise<StrengthEstimator> | null = null;

/**
 * Load zxcvbn-ts with the English and common dictionaries. The dictionaries are
 * about a megabyte, so they are imported lazily and cached after the first call.
 */
export function loadStrengthEstimator(): Promise<StrengthEstimator> {
  estimator ??= (async () => {
    const [{ ZxcvbnFactory }, common, en] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    const factory = new ZxcvbnFactory({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary },
      // Off on purpose: fuzzy matching against every dictionary cost about a
      // second per check, too slow to run as someone types. Near-misses of
      // common passwords still score low through the l33t and reversed rules.
      useLevenshteinDistance: false,
      maxLength: MAX_LENGTH,
      timeEstimationValues: TIME_ESTIMATION_VALUES,
    });
    return createEstimator(factory);
  })();
  return estimator;
}

function createEstimator(factory: ZxcvbnFactory): StrengthEstimator {
  return {
    check(password, userInputs) {
      const r = factory.check(password, userInputs);
      const sequence = r.sequence as MatchEstimated[];
      const weaknesses: Weakness[] = [];
      let bruteforceChars = 0;
      for (const m of sequence) {
        const w = describe(m);
        if (w) weaknesses.push(w);
        else if (m.pattern === "bruteforce") bruteforceChars += m.j - m.i + 1;
      }
      return {
        score: r.score,
        label: SCORE_LABELS[r.score],
        guesses: r.guesses,
        guessesLog10: r.guessesLog10,
        crackTimes: ATTACK_MODELS.map((model) => ({
          ...model,
          seconds: r.crackTimes[model.id].seconds,
          display: r.crackTimes[model.id].display,
        })),
        weaknesses,
        bruteforceChars,
        feedback: { warning: r.feedback.warning || null, suggestions: [...r.feedback.suggestions] },
        length: [...password].length,
        truncated: password.length > MAX_LENGTH,
        calcTimeMs: r.calcTime,
      };
    },
  };
}

function base(m: MatchEstimated, kind: WeaknessKind, title: string, detail: string, note?: string): Weakness {
  return {
    kind,
    title,
    detail,
    i: m.i,
    j: m.j,
    length: m.j - m.i + 1,
    guessesLog10: m.guessesLog10,
    revealed: { token: m.token, ...(note ? { note } : {}) },
  };
}

const DICTIONARY_LABEL: Record<string, string> = {
  passwords: "a list of passwords leaked in past breaches",
  commonWords: "a list of common English words",
  wikipedia: "words that appear often on English Wikipedia",
  firstnames: "a list of common first names",
  lastnames: "a list of common surnames",
  diceware: "a diceware passphrase wordlist",
  userInputs: "words specific to this page",
};

/** Short themed lists zxcvbn-ts ships for English (months, planets, ...). */
const THEMED_LABEL: Record<string, string> = {
  cardinalNumbers: "numbers spelled out",
  ordinalNumbers: "ordinal numbers",
  daysOfWeek: "days of the week",
  months: "months",
  seasons: "seasons",
  timePeriods: "time periods",
  rainbowColors: "colours of the rainbow",
  directions: "compass directions",
  intermediateDirections: "compass directions",
  sizeProgression: "size words",
  militaryAlphabet: "the NATO phonetic alphabet",
  planets: "planets",
  zodiacSigns: "zodiac signs",
  chineseZodiac: "Chinese zodiac animals",
};

function dictionaryFamily(name: string): string {
  return name.replace(/-(en|common)$/, "");
}

function dictionarySource(family: string): string {
  const themed = THEMED_LABEL[family];
  if (themed) return `a short list of ${themed}`;
  return DICTIONARY_LABEL[family] ?? "a wordlist";
}

/** Turn one zxcvbn match into a plain-language weakness, or null for brute-force and separators. */
export function describe(m: MatchEstimated): Weakness | null {
  switch (m.pattern) {
    case "dictionary": {
      const d = m as DictionaryMatch & Partial<L33tMatch> & MatchEstimated;
      const family = dictionaryFamily(String(d.dictionaryName));
      const source = dictionarySource(family);
      const rankNote = `"${d.matchedWord}", rank ${d.rank.toLocaleString("en-US")} in ${source}`;
      if (d.l33t) {
        const subs = (d.subs ?? []).map((s) => `${s.substitution} for ${s.letter}`).join(", ");
        return base(
          m,
          "l33t",
          "Letter substitution",
          `A dictionary word with symbols swapped in for letters. Cracking tools apply these swaps automatically, so they add very little.`,
          `${rankNote}; swaps: ${subs}`,
        );
      }
      if (d.reversed) {
        return base(
          m,
          "reversed",
          "Reversed word",
          "A dictionary word spelled backwards. Reversal is one of the first rules cracking tools try.",
          rankNote,
        );
      }
      if (family === "passwords") {
        return base(
          m,
          "common-password",
          "Common password",
          "Appears in lists of real passwords leaked in past breaches. Attackers try these first.",
          rankNote,
        );
      }
      if (family === "firstnames" || family === "lastnames") {
        return base(m, "name", "Name", "A common first name or surname. Names are in every cracking wordlist.", rankNote);
      }
      if (family === "userInputs") {
        return base(m, "personal", "Page or personal data", "Matches a word tied to this page or to you, which an attacker would try early.", rankNote);
      }
      return base(
        m,
        "dictionary-word",
        "Dictionary word",
        "A word from a standard wordlist. Single words fall fast; several random ones together do not.",
        rankNote,
      );
    }
    case "spatial": {
      const s = m as SpatialMatch & MatchEstimated;
      return base(
        m,
        "keyboard-walk",
        "Keyboard walk",
        `Keys next to each other on a ${s.graph} layout${s.turns > 1 ? `, with ${s.turns} changes of direction` : ""}. Walks are enumerated by cracking tools.`,
      );
    }
    case "repeat": {
      const r = m as RepeatMatch & MatchEstimated;
      return base(
        m,
        "repeat",
        "Repeated pattern",
        `The same ${typeof r.baseToken === "string" && r.baseToken.length === 1 ? "character" : "chunk"} repeated ${r.repeatCount} times. Repeating adds length, not much strength.`,
        `repeats "${Array.isArray(r.baseToken) ? r.baseToken.join("") : r.baseToken}"`,
      );
    }
    case "sequence": {
      const s = m as SequenceMatch & MatchEstimated;
      const space = s.sequenceName === "digits" ? "digits" : s.sequenceName === "lower" || s.sequenceName === "upper" ? "letters" : "characters";
      return base(m, "sequence", "Sequence", `A run of ${space} in ${s.ascending ? "ascending" : "descending"} order, like abc or 321.`);
    }
    case "wordSequence": {
      const w = m as WordSequenceMatch & MatchEstimated;
      return base(m, "word-sequence", "Word sequence", `${w.wordCount} words in a well-known order, like days of the week or months.`);
    }
    case "date": {
      const d = m as DateMatch & MatchEstimated;
      return base(
        m,
        "date",
        "Date",
        "A calendar date. Birthdays and anniversaries are guessed early, and there are only about 365 a year.",
        `${d.year}-${String(d.month).padStart(2, "0")}-${String(d.day).padStart(2, "0")}`,
      );
    }
    case "regex": {
      const r = m as RegexMatch & MatchEstimated;
      if (r.regexName === "recentYear") {
        return base(m, "recent-year", "Recent year", "A year from the last century or so. Years are among the first things appended in cracking rules.");
      }
      return null;
    }
    default:
      return null;
  }
}

/** Format a guesses-per-second rate for display, e.g. 1e10 -> "10 billion / s". */
export function formatRate(perSecond: number): string {
  if (perSecond < 1) {
    const perHour = Math.round(perSecond * 3600);
    return `${perHour.toLocaleString("en-US")} / hour`;
  }
  const units: [number, string][] = [
    [1e12, "trillion"],
    [1e9, "billion"],
    [1e6, "million"],
  ];
  for (const [n, name] of units) {
    if (perSecond >= n) return `${trim(perSecond / n)} ${name} / s`;
  }
  return `${perSecond.toLocaleString("en-US")} / s`;
}

function trim(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}
