# Portfolio entry (draft)

Draft for `src/content/projects.ts` in saafirhale-site, in the shape of its `Project` type. Every
claim below can be checked against this repo: the code, the tests (`npm test`) or the README.

`status` is `"live"` because the source is public at https://github.com/SaafirHale/pwcheck. When the
tool is deployed at `/tools/password`, add that as a second link.

```ts
{
  slug: "password-strength-breach-checker",
  category: "security",
  title: "Password Strength & Breach Checker",
  blurb:
    "A browser tool that shows how a password would be guessed and whether it is in breach data, without the password leaving the page.",
  body: [
    "Strength comes from zxcvbn-ts with its English and common-password dictionaries. Each pattern it finds (common password, dictionary word, name, letter substitution, reversed word, keyboard walk, repeat, sequence, date, recent year) is explained in plain language, alongside crack times under four attack models: online throttled, online unthrottled, offline against a slow hash such as bcrypt, and offline against a fast hash.",
    "The breach check uses Have I Been Pwned's Pwned Passwords range API with k-anonymity. The SHA-1 is computed locally with Web Crypto, only the first five hex characters are sent, and the other 35 are matched in the page. The request asks for padded responses so their size gives nothing away. The page shows exactly what was sent, and a switch turns the check off for strength-only use with no network requests.",
    "The check runs on a button press, never per keystroke. Checking as you type would send a hash prefix for every short fragment of the password, and fragments that short can be brute-forced from their prefixes, leaking the password a character at a time. The README's threat model covers this along with what the prefix still reveals, padding, and the limits of what a web page can protect.",
    "A passphrase generator draws from the EFF Large Wordlist with crypto.getRandomValues and rejection sampling, and shows the exact entropy: about 12.9 bits per word, 77.5 bits for six. The k-anonymity logic is tested against a recorded, padded range response, covering the prefix/suffix split, dropped padding entries and case handling.",
  ],
  stack: ["TypeScript", "React", "zxcvbn-ts", "Web Crypto", "Have I Been Pwned API", "Vitest"],
  links: [{ label: "github.com/SaafirHale/pwcheck", href: "https://github.com/SaafirHale/pwcheck" }],
  status: "live",
},
```

## Claims and where to verify them

| Claim | Evidence |
| --- | --- |
| Only the 5-character prefix is sent | `src/core/hibp.ts` `checkPwned`; `test/hibp.test.ts` "sends only the prefix and matches the suffix locally" |
| Padding requested and padding entries ignored | `rangeRequestInit`, `parseRange`; tests "drops padding entries", "returns 0 for a padding suffix" |
| Case handling | test "matches regardless of case on either side", "uppercases lowercase input" |
| No network requests with the check off | `PasswordChecker.tsx` `runBreachCheck` returns early when off; verified in the browser preview (no off-origin requests after typing and pressing Enter) |
| Ten weakness kinds explained | `src/core/strength.ts` `describe`; `test/strength.test.ts` "weaknesses" |
| Four attack models | `ATTACK_MODELS` in `strength.ts`; test "returns one row per attack model" |
| 12.9 bits per word, 77.5 for six | `passphrase.ts`; test "is log2(7776) bits per word" |
| Rejection sampling | `uniformIndex`; test "rejects values in the biased tail" |
