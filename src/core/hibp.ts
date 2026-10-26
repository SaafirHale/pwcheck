// Pwned Passwords range lookup with k-anonymity.
//
// The password is hashed with SHA-1 locally. Only the first five hex characters
// of that hash go over the network; the service answers with every hash suffix
// it holds under that prefix, and the match against our own suffix happens
// here. With Add-Padding, the response is filled out with fake suffixes whose
// count is 0, so its size does not hint at how many real entries the prefix has.

export const RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";

export const PREFIX_LENGTH = 5;

export type HashParts = {
  /** First five hex characters, uppercase. The only part that is sent. */
  prefix: string;
  /** Remaining 35 hex characters, uppercase. Never leaves the page. */
  suffix: string;
};

export type RangeEntries = {
  /** Real entries only, keyed by uppercase suffix. Padding entries are dropped. */
  counts: Map<string, number>;
  /** Number of real entries in the response. */
  real: number;
  /** Number of padding entries (count 0) in the response. */
  padding: number;
};

export type BreachResult = {
  /** The five characters that were sent. */
  prefix: string;
  /** Times the password appears in the Pwned Passwords corpus. 0 = not found. */
  count: number;
  /** Real entries returned for the prefix. */
  realEntries: number;
  /** Padding entries returned for the prefix (ignored for matching). */
  paddingEntries: number;
  /** Size of the response body in characters. */
  responseLength: number;
  /** Exact URL requested. Contains only the prefix. */
  url: string;
};

export class RangeParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RangeParseError";
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Pick<Response, "ok" | "status" | "text">>;

/** Uppercase hex SHA-1 of the UTF-8 bytes of `input`, computed with Web Crypto. */
export async function sha1Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  try {
    const digest = await crypto.subtle.digest("SHA-1", bytes);
    let hex = "";
    for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, "0");
    return hex.toUpperCase();
  } finally {
    // The encoded password does not need to outlive the hash.
    bytes.fill(0);
  }
}

/** Split a 40-character SHA-1 hex string into the 5-character prefix and 35-character suffix. */
export function splitHash(sha1: string): HashParts {
  const hex = sha1.trim().toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(hex)) {
    throw new RangeParseError("Expected a 40-character SHA-1 hex string");
  }
  return { prefix: hex.slice(0, PREFIX_LENGTH), suffix: hex.slice(PREFIX_LENGTH) };
}

/**
 * Parse a range response: one `SUFFIX:COUNT` per line, CRLF or LF.
 * Suffixes are uppercased; padding entries (count 0) are counted but dropped.
 * A malformed line throws rather than being skipped, so a garbled response is
 * never reported as "not found".
 */
export function parseRange(body: string): RangeEntries {
  const counts = new Map<string, number>();
  let padding = 0;
  const lines = body.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n]!.trim();
    if (line === "") continue;
    const m = /^([0-9A-Fa-f]{35}):(\d+)$/.exec(line);
    if (!m) throw new RangeParseError(`Unexpected line ${n + 1} in range response`);
    const count = Number(m[2]);
    if (count === 0) {
      padding++;
      continue;
    }
    counts.set(m[1]!.toUpperCase(), count);
  }
  return { counts, real: counts.size, padding };
}

/** Count for `suffix` in a range response body, or 0 if absent or only present as padding. */
export function matchSuffix(body: string, suffix: string): number {
  return parseRange(body).counts.get(suffix.toUpperCase()) ?? 0;
}

export function rangeUrl(prefix: string, endpoint = RANGE_ENDPOINT): string {
  if (!/^[0-9A-F]{5}$/.test(prefix)) throw new RangeParseError("Prefix must be 5 uppercase hex characters");
  return endpoint + prefix;
}

/** Request options for the range call. Exported so tests can assert them. */
export function rangeRequestInit(signal?: AbortSignal): RequestInit {
  return {
    method: "GET",
    headers: { "Add-Padding": "true" },
    mode: "cors",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    signal,
  };
}

export type CheckOptions = {
  fetch?: FetchLike;
  signal?: AbortSignal;
  endpoint?: string;
};

/** Full k-anonymity check: hash locally, send the prefix, match the suffix locally. */
export async function checkPwned(password: string, options: CheckOptions = {}): Promise<BreachResult> {
  const doFetch: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const { prefix, suffix } = splitHash(await sha1Hex(password));
  const url = rangeUrl(prefix, options.endpoint);
  const res = await doFetch(url, rangeRequestInit(options.signal));
  if (!res.ok) throw new Error(`Pwned Passwords returned HTTP ${res.status}`);
  const body = await res.text();
  const entries = parseRange(body);
  return {
    prefix,
    count: entries.counts.get(suffix) ?? 0,
    realEntries: entries.real,
    paddingEntries: entries.padding,
    responseLength: body.length,
    url,
  };
}
