import { beforeAll, describe, expect, it } from "vitest";
import {
  ATTACK_MODELS,
  formatRate,
  loadStrengthEstimator,
  TIME_ESTIMATION_VALUES,
  type StrengthEstimator,
  type WeaknessKind,
} from "../src/core/strength.js";

let est: StrengthEstimator;

beforeAll(async () => {
  est = await loadStrengthEstimator();
}, 30_000);

function kinds(password: string): WeaknessKind[] {
  return est.check(password).weaknesses.map((w) => w.kind);
}

describe("weaknesses", () => {
  const cases: [string, WeaknessKind][] = [
    ["password", "common-password"],
    ["p@ssw0rd", "l33t"],
    ["drowssap", "reversed"],
    ["asdfghjkl;'", "keyboard-walk"],
    ["abcabcabcabc", "repeat"],
    ["abcdefg", "sequence"],
    ["mondaytuesdaywednesday", "word-sequence"],
    ["12/25/1990x", "date"],
    ["summer2019", "recent-year"],
    ["summer2019", "dictionary-word"],
    ["Fitzgerald", "name"],
  ];

  it.each(cases)("%s is flagged as %s", (password, kind) => {
    expect(kinds(password)).toContain(kind);
  });

  it("flags words passed as user inputs as personal", () => {
    const w = est.check("saafirhale99", ["saafirhale"]).weaknesses[0]!;
    expect(w.kind).toBe("personal");
    expect(w.revealed.token).toBe("saafirhale");
  });

  it("explains l33t swaps in the revealed note", () => {
    const w = est.check("p@ssw0rd").weaknesses[0]!;
    expect(w.revealed.note).toContain('"password"');
    expect(w.revealed.note).toContain("@ for a");
    expect(w.revealed.note).toContain("0 for o");
  });

  it("gives themed lists a readable source", () => {
    const w = est.check("summer2019").weaknesses.find((x) => x.kind === "dictionary-word")!;
    expect(w.revealed.note).toContain("a short list of seasons");
  });

  it("never puts any part of the password in title or detail", () => {
    // "password" itself is left out: the fixed copy says "password".
    const samples = ["letmein", "p@ssw0rd", "drowssap", "asdfghjkl;'", "abcabcabcabc", "Michael1987", "12/25/1990x", "summer2019"];
    for (const p of samples) {
      for (const w of est.check(p).weaknesses) {
        expect(`${w.title} ${w.detail}`.toLowerCase()).not.toContain(w.revealed.token.toLowerCase());
      }
    }
  });

  it("reports nothing for random characters and prices them as brute force", () => {
    const r = est.check("Kx9#vQ2!mZ7$");
    expect(r.weaknesses).toEqual([]);
    expect(r.bruteforceChars).toBe(12);
  });
});

describe("score and feedback", () => {
  it("scores a top password 0 with zxcvbn's warning", () => {
    const r = est.check("password");
    expect(r.score).toBe(0);
    expect(r.label).toBe("Too guessable");
    expect(r.feedback.warning).toBe("This is a heavily used password.");
  });

  it("scores a six-word passphrase 4", () => {
    expect(est.check("tiger-oblong-ruffle-cubical-sprung-vowel").score).toBe(4);
  });

  it("flags passwords past the length limit as truncated", () => {
    expect(est.check("a".repeat(300)).truncated).toBe(true);
    expect(est.check("a".repeat(30)).truncated).toBe(false);
  });

  it("counts length in code points, not UTF-16 units", () => {
    expect(est.check("🔑🔑🔑").length).toBe(3);
  });
});

describe("crack times", () => {
  it("returns one row per attack model, in order", () => {
    const r = est.check("summer2019");
    expect(r.crackTimes.map((c) => c.id)).toEqual(ATTACK_MODELS.map((m) => m.id));
  });

  it("is guesses divided by each model's rate", () => {
    const r = est.check("summer2019");
    for (const row of r.crackTimes) {
      expect(row.seconds).toBeCloseTo(r.guesses / row.perSecond, 6);
    }
  });

  it("uses zxcvbn-ts's default rates", () => {
    expect(TIME_ESTIMATION_VALUES.attackTime).toEqual({
      onlineThrottlingXPerHour: 100,
      onlineNoThrottlingXPerSecond: 10,
      offlineSlowHashingXPerSecond: 1e4,
      offlineFastHashingXPerSecond: 1e10,
    });
  });

  it("orders fastest attack last", () => {
    const secs = est.check("summer2019").crackTimes.map((c) => c.seconds);
    expect([...secs].sort((a, b) => b - a)).toEqual(secs);
  });
});

describe("formatRate", () => {
  it("formats each model's rate", () => {
    expect(ATTACK_MODELS.map((m) => formatRate(m.perSecond))).toEqual([
      "100 / hour",
      "10 / s",
      "10,000 / s",
      "10 billion / s",
    ]);
  });
});
