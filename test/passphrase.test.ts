import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EFF_LARGE_WORDLIST, EFF_LARGE_WORDLIST_SHA256 } from "../src/core/eff-large-wordlist.js";
import {
  BITS_PER_WORD,
  entropyBits,
  generatePassphrase,
  uniformIndex,
  type RandomSource,
} from "../src/core/passphrase.js";

/** Random source that hands out a fixed sequence of 32-bit values. */
function scripted(values: number[]): RandomSource & { used: number } {
  const fn = ((a: Uint32Array) => {
    for (let k = 0; k < a.length; k++) {
      if (fn.used >= values.length) throw new Error("scripted random ran out");
      a[k] = values[fn.used++]!;
    }
    return a;
  }) as RandomSource & { used: number };
  fn.used = 0;
  return fn;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("EFF large wordlist", () => {
  it("has 7,776 unique lowercase words", () => {
    expect(EFF_LARGE_WORDLIST).toHaveLength(7776);
    expect(new Set(EFF_LARGE_WORDLIST).size).toBe(7776);
    expect(EFF_LARGE_WORDLIST.every((w) => /^[a-z-]+$/.test(w))).toBe(true);
    expect(EFF_LARGE_WORDLIST[0]).toBe("abacus");
    expect(EFF_LARGE_WORDLIST[7775]).toBe("zoom");
  });

  it("matches the vendored EFF file, in order", () => {
    const raw = readFileSync(new URL("../data/eff_large_wordlist.txt", import.meta.url));
    expect(createHash("sha256").update(raw).digest("hex")).toBe(EFF_LARGE_WORDLIST_SHA256);
    const words = raw.toString("utf8").split(/\r?\n/).filter(Boolean).map((l) => l.split("\t")[1]);
    expect(words).toEqual([...EFF_LARGE_WORDLIST]);
  });
});

describe("uniformIndex", () => {
  it("rejects values in the biased tail", () => {
    const n = 7776;
    const limit = Math.floor(2 ** 32 / n) * n;
    const random = scripted([limit, 2 ** 32 - 1, n + 5]);
    expect(uniformIndex(n, random)).toBe(5);
    expect(random.used).toBe(3);
  });

  it("accepts the last unbiased value", () => {
    const n = 7776;
    const limit = Math.floor(2 ** 32 / n) * n;
    expect(uniformIndex(n, scripted([limit - 1]))).toBe((limit - 1) % n);
  });

  it("uses crypto.getRandomValues by default", () => {
    const spy = vi.spyOn(globalThis.crypto, "getRandomValues");
    uniformIndex(10);
    expect(spy).toHaveBeenCalled();
  });

  it("stays in range over many draws", () => {
    for (let k = 0; k < 5000; k++) {
      const x = uniformIndex(7776);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThan(7776);
    }
  });
});

describe("generatePassphrase", () => {
  it("picks words by index from the scripted source", () => {
    const p = generatePassphrase({ words: 4, random: scripted([0, 1, 7775, 2]) });
    expect(p.words).toEqual(["abacus", "abdomen", "zoom", "abdominal"]);
    expect(p.passphrase).toBe("abacus-abdomen-zoom-abdominal");
  });

  it("applies separator and capitalisation", () => {
    const p = generatePassphrase({ words: 3, separator: " ", capitalize: true, random: scripted([0, 1, 7775]) });
    expect(p.passphrase).toBe("Abacus Abdomen Zoom");
  });

  it("appends a random digit when asked", () => {
    const p = generatePassphrase({ words: 3, digit: true, random: scripted([0, 1, 2, 7]) });
    expect(p.passphrase).toBe("abacus-abdomen-abdominal7");
  });

  it("defaults to six words from crypto.getRandomValues", () => {
    const spy = vi.spyOn(globalThis.crypto, "getRandomValues");
    const p = generatePassphrase();
    expect(p.words).toHaveLength(6);
    expect(p.words.every((w) => EFF_LARGE_WORDLIST.includes(w))).toBe(true);
    expect(spy).toHaveBeenCalledTimes(6);
  });

  it("rejects word counts out of range and an empty separator", () => {
    expect(() => generatePassphrase({ words: 2 })).toThrow(RangeError);
    expect(() => generatePassphrase({ words: 13 })).toThrow(RangeError);
    expect(() => generatePassphrase({ words: 4.5 })).toThrow(RangeError);
    expect(() => generatePassphrase({ separator: "" })).toThrow(RangeError);
  });
});

describe("entropy", () => {
  it("is log2(7776) bits per word", () => {
    expect(BITS_PER_WORD).toBeCloseTo(12.925, 3);
    expect(entropyBits(6)).toBeCloseTo(77.55, 2);
    expect(generatePassphrase({ words: 5 }).entropyBits).toBeCloseTo(5 * Math.log2(7776), 10);
  });

  it("adds log2(10) for the digit and nothing for separator or capitals", () => {
    expect(entropyBits(6, true) - entropyBits(6)).toBeCloseTo(Math.log2(10), 10);
    const a = generatePassphrase({ words: 6, separator: ".", capitalize: true });
    expect(a.entropyBits).toBe(entropyBits(6));
  });
});
