// Passphrase generator over the EFF large wordlist.
//
// Each word is an independent, uniform pick from 7,776 words, drawn with
// crypto.getRandomValues and rejection sampling so no word is more likely than
// another. The entropy reported is exact for that process: log2(7776) bits per
// word, plus log2(10) if a random digit is appended. Separators and
// capitalisation are fixed choices, not random, so they add nothing.

import { EFF_LARGE_WORDLIST } from "./eff-large-wordlist.js";

export type RandomSource = (array: Uint32Array) => Uint32Array;

export type PassphraseOptions = {
  /** Number of words, 3 to 12. Default 6. */
  words?: number;
  /** Placed between words. Default "-". Must be non-empty so word boundaries stay unambiguous. */
  separator?: string;
  /** Capitalise the first letter of each word. Adds no entropy. Default false. */
  capitalize?: boolean;
  /** Append one random digit, for sites that insist on one. Adds log2(10) bits. Default false. */
  digit?: boolean;
  /** Override the random source (tests). Defaults to crypto.getRandomValues. */
  random?: RandomSource;
};

export type Passphrase = {
  passphrase: string;
  words: string[];
  entropyBits: number;
};

export const WORDLIST_SIZE = EFF_LARGE_WORDLIST.length;
export const BITS_PER_WORD = Math.log2(WORDLIST_SIZE);
export const MIN_WORDS = 3;
export const MAX_WORDS = 12;

const defaultRandom: RandomSource = (a) => crypto.getRandomValues(a);

/** Uniform integer in [0, n) from 32-bit random values, rejecting the biased tail. */
export function uniformIndex(n: number, random: RandomSource = defaultRandom): number {
  if (!Number.isInteger(n) || n < 1 || n > 2 ** 32) throw new RangeError("n must be an integer in [1, 2^32]");
  const limit = Math.floor(2 ** 32 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    random(buf);
    const x = buf[0]!;
    if (x < limit) {
      buf[0] = 0;
      return x % n;
    }
  }
}

export function entropyBits(words: number, digit = false): number {
  return words * BITS_PER_WORD + (digit ? Math.log2(10) : 0);
}

export function generatePassphrase(options: PassphraseOptions = {}): Passphrase {
  const count = options.words ?? 6;
  if (!Number.isInteger(count) || count < MIN_WORDS || count > MAX_WORDS) {
    throw new RangeError(`words must be an integer from ${MIN_WORDS} to ${MAX_WORDS}`);
  }
  const separator = options.separator ?? "-";
  if (separator === "") throw new RangeError("separator must not be empty");
  const random = options.random ?? defaultRandom;

  const words: string[] = [];
  for (let k = 0; k < count; k++) {
    const w = EFF_LARGE_WORDLIST[uniformIndex(WORDLIST_SIZE, random)]!;
    words.push(options.capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w);
  }
  let passphrase = words.join(separator);
  if (options.digit) passphrase += String(uniformIndex(10, random));

  return { passphrase, words, entropyBits: entropyBits(count, options.digit) };
}
