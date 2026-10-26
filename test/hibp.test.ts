import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  checkPwned,
  matchSuffix,
  parseRange,
  rangeRequestInit,
  rangeUrl,
  RangeParseError,
  RANGE_ENDPOINT,
  sha1Hex,
  splitHash,
  type FetchLike,
} from "../src/core/hibp.js";

// Recorded from https://api.pwnedpasswords.com/range/5BAA6 with "Add-Padding: true"
// on 26 Oct 2026. Stored byte-for-byte (CRLF line endings), see .gitattributes.
const FIXTURE = readFileSync(new URL("./fixtures/range-5BAA6.txt", import.meta.url), "utf8");
const FIXTURE_LINES = FIXTURE.split("\r\n").filter(Boolean);
const FIXTURE_PADDING = FIXTURE_LINES.filter((l) => l.endsWith(":0"));

// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
const PASSWORD_COUNT_IN_FIXTURE = 52372427;

function nodeSha1(s: string): string {
  return createHash("sha1").update(s, "utf8").digest("hex").toUpperCase();
}

describe("sha1Hex", () => {
  it("hashes with Web Crypto and returns uppercase hex", async () => {
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  });

  it("hashes the UTF-8 bytes, matching what the corpus was built from", async () => {
    for (const s of ["pässwörd", "密码", "🔑🔑🔑", "", " leading and trailing "]) {
      expect(await sha1Hex(s)).toBe(nodeSha1(s));
    }
  });
});

describe("splitHash", () => {
  it("splits into a 5-character prefix and 35-character suffix", () => {
    const { prefix, suffix } = splitHash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    expect(prefix).toBe("5BAA6");
    expect(suffix).toBe(PASSWORD_SUFFIX);
    expect(prefix.length + suffix.length).toBe(40);
  });

  it("uppercases lowercase input", () => {
    expect(splitHash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")).toEqual({
      prefix: "5BAA6",
      suffix: PASSWORD_SUFFIX,
    });
  });

  it("rejects anything that is not 40 hex characters", () => {
    expect(() => splitHash("5BAA6")).toThrow(RangeParseError);
    expect(() => splitHash("Z".repeat(40))).toThrow(RangeParseError);
    expect(() => splitHash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8AA")).toThrow(RangeParseError);
  });
});

describe("parseRange against the recorded fixture", () => {
  it("has the shape of a padded response", () => {
    // Sanity checks on the recording itself, so the tests below mean something.
    expect(FIXTURE).toContain("\r\n");
    expect(FIXTURE_LINES.length).toBeGreaterThan(800);
    expect(FIXTURE_PADDING.length).toBeGreaterThan(0);
  });

  it("counts every line as either a real entry or padding", () => {
    const r = parseRange(FIXTURE);
    expect(r.padding).toBe(FIXTURE_PADDING.length);
    expect(r.real + r.padding).toBe(FIXTURE_LINES.length);
    expect(r.counts.size).toBe(r.real);
  });

  it("drops padding entries (count 0) from the lookup table", () => {
    const r = parseRange(FIXTURE);
    for (const line of FIXTURE_PADDING) {
      const suffix = line.split(":")[0]!;
      expect(r.counts.has(suffix)).toBe(false);
    }
    expect([...r.counts.values()].every((c) => c > 0)).toBe(true);
  });

  it("finds the suffix for 'password' with its recorded count", () => {
    expect(matchSuffix(FIXTURE, PASSWORD_SUFFIX)).toBe(PASSWORD_COUNT_IN_FIXTURE);
  });

  it("returns 0 for a padding suffix even though it appears in the body", () => {
    const paddingSuffix = FIXTURE_PADDING[0]!.split(":")[0]!;
    expect(FIXTURE).toContain(paddingSuffix);
    expect(matchSuffix(FIXTURE, paddingSuffix)).toBe(0);
  });

  it("returns 0 for a suffix that is not in the body", () => {
    expect(matchSuffix(FIXTURE, "0".repeat(35))).toBe(0);
  });

  it("matches regardless of case on either side", () => {
    expect(matchSuffix(FIXTURE, PASSWORD_SUFFIX.toLowerCase())).toBe(PASSWORD_COUNT_IN_FIXTURE);
    expect(matchSuffix(FIXTURE.toLowerCase(), PASSWORD_SUFFIX)).toBe(PASSWORD_COUNT_IN_FIXTURE);
  });

  it("accepts LF line endings and a trailing newline", () => {
    const lf = FIXTURE.replace(/\r\n/g, "\n") + "\n";
    expect(parseRange(lf).real).toBe(parseRange(FIXTURE).real);
    expect(matchSuffix(lf, PASSWORD_SUFFIX)).toBe(PASSWORD_COUNT_IN_FIXTURE);
  });
});

describe("parseRange on malformed input", () => {
  it("throws instead of reporting a garbled response as 'not found'", () => {
    expect(() => parseRange("<html>Service Unavailable</html>")).toThrow(RangeParseError);
    expect(() => parseRange(`${PASSWORD_SUFFIX}:12\r\nnot-a-line\r\n`)).toThrow(/line 2/);
    expect(() => parseRange(`${PASSWORD_SUFFIX.slice(1)}:12`)).toThrow(RangeParseError);
    expect(() => parseRange(`${PASSWORD_SUFFIX}:-1`)).toThrow(RangeParseError);
  });

  it("treats an empty body as no entries", () => {
    expect(parseRange("")).toEqual({ counts: new Map(), real: 0, padding: 0 });
  });
});

describe("rangeUrl and request options", () => {
  it("builds the URL from the prefix alone", () => {
    expect(rangeUrl("5BAA6")).toBe("https://api.pwnedpasswords.com/range/5BAA6");
    expect(() => rangeUrl("5baa6")).toThrow();
    expect(() => rangeUrl("5BAA61")).toThrow();
  });

  it("asks for padding and sends no credentials, cache or referrer", () => {
    const init = rangeRequestInit();
    expect(init.headers).toEqual({ "Add-Padding": "true" });
    expect(init.credentials).toBe("omit");
    expect(init.cache).toBe("no-store");
    expect(init.referrerPolicy).toBe("no-referrer");
    expect(init.method).toBe("GET");
  });
});

describe("checkPwned", () => {
  type Call = { url: string; init?: RequestInit };

  function fakeFetch(body: string, status = 200): { fetch: FetchLike; calls: Call[] } {
    const calls: Call[] = [];
    return {
      calls,
      fetch: async (url, init) => {
        calls.push({ url, init });
        return { ok: status >= 200 && status < 300, status, text: async () => body };
      },
    };
  }

  it("sends only the prefix and matches the suffix locally", async () => {
    const f = fakeFetch(FIXTURE);
    const result = await checkPwned("password", { fetch: f.fetch });

    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe(`${RANGE_ENDPOINT}5BAA6`);
    expect((init?.headers as Record<string, string>)["Add-Padding"]).toBe("true");

    // Nothing in the request carries the password or the rest of its hash.
    expect(new URL(url).pathname).toBe("/range/5BAA6");
    expect(new URL(url).search).toBe("");
    const sent = new URL(url).pathname + JSON.stringify({ ...init, signal: undefined });
    expect(sent.toLowerCase()).not.toContain("password");
    expect(sent.toUpperCase()).not.toContain(PASSWORD_SUFFIX);
    expect(sent.toUpperCase()).not.toContain(PASSWORD_SUFFIX.slice(0, 8));

    expect(result).toEqual({
      prefix: "5BAA6",
      count: PASSWORD_COUNT_IN_FIXTURE,
      realEntries: FIXTURE_LINES.length - FIXTURE_PADDING.length,
      paddingEntries: FIXTURE_PADDING.length,
      responseLength: FIXTURE.length,
      url: `${RANGE_ENDPOINT}5BAA6`,
    });
  });

  it("reports 0 when the suffix is not in the range", async () => {
    // Any password whose hash does not appear in the body. The fake ignores the prefix.
    const f = fakeFetch(FIXTURE);
    const result = await checkPwned("correct-horse-battery-staple-k7", { fetch: f.fetch });
    expect(result.count).toBe(0);
    expect(f.calls[0]!.url).toBe(`${RANGE_ENDPOINT}${(await sha1Hex("correct-horse-battery-staple-k7")).slice(0, 5)}`);
  });

  it("throws on an HTTP error rather than reporting 'not found'", async () => {
    await expect(checkPwned("password", { fetch: fakeFetch("", 503).fetch })).rejects.toThrow(/503/);
  });

  it("passes the abort signal through", async () => {
    const f = fakeFetch(FIXTURE);
    const ac = new AbortController();
    await checkPwned("password", { fetch: f.fetch, signal: ac.signal });
    expect(f.calls[0]!.init?.signal).toBe(ac.signal);
  });
});
