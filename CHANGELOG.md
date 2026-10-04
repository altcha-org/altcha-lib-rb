# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.0.0] - 2026-10-04

Brings `Altcha::V2` in line with the reference JS implementation: challenges, solutions and signatures now interoperate in both directions.

### Breaking changes

- Ruby 3.0 or newer is required. v2 already needed it: `OpenSSL.fixed_length_secure_compare` does not exist on Ruby 2.7.
- `ARGON2ID` uses `memory_cost` exactly, in KiB; it was rounded to a power of two before. `memory_cost` is now required and has no 64 MiB default. ARGON2ID challenges created earlier with a memory cost that is not a power of two no longer verify.
- `hmac_algorithm` accepts only `'SHA-256'`, `'SHA-384'` and `'SHA-512'`, matched exactly. Anything else, including `'SHA-1'`, lowercase names and `nil`, raises `ArgumentError`. Before, unknown values silently used SHA-256.
- `verify_fields_hash` raises `ArgumentError` for any algorithm other than `'SHA-256'`, `'SHA-384'` or `'SHA-512'`. Before, unknown values silently used SHA-256.
- `verify_solution` raises `ArgumentError` when `hmac_signature_secret` is `nil` or `''`.
- `create_challenge` treats `''` secrets as unset, as JS does. An empty `hmac_signature_secret` returns an unsigned challenge, and an empty `hmac_key_signature_secret` adds no `keySignature`.
- `solve_challenge` gives up after 90 seconds by default and returns `nil`. Pass `timeout: nil` to keep the old unlimited behaviour.
- `expires_at` is compared with sub-second precision, so there is no longer up to 1 second of extra validity. `expires_at: 0` means "no expiry" instead of "expired".
- In `uint32` counter mode, `verify_solution` accepts only whole-number counters from 0 to 2^32−1. Values that wrap to a valid counter, such as `c + 2^32`, are rejected as `invalid_solution`. JS accepts them, so this is stricter.
- The signed JSON now includes unknown and `null` challenge parameters exactly as received, so adding a field to a challenge invalidates its signature. A challenge without `keyLength` or `keyPrefix` no longer has the defaults added to its signed JSON.
- `canonical_json` output changed for floats, integer-like keys, keys sorted by UTF-16 code unit, and objects inside arrays (see below). Challenges that were signed before upgrading and contain such `data` fail verification once.

### Added

- `counter_mode` option (`'uint32'`, the default, or `'string'`) for `create_challenge`, `solve_challenge` and `verify_solution`, matching JS `counterMode`. Unknown values raise `ArgumentError`.
- `hmac_algorithm` option for `create_challenge`. It is used for both the challenge signature and `keySignature`.
- `timeout` option for `solve_challenge`, in milliseconds (default `90_000`).
- `ChallengeParameters#extra`, which holds parameter keys without a matching attribute so they are signed exactly as received.

### Fixed

- `canonical_json` writes numbers like JS `JSON.stringify` (`1.0` → `1`, `1e-7` → `1e-7`, integers above 2^53 rounded to a double) and orders keys like JS: integer-like keys first in numeric order, other keys by UTF-16 code unit, objects inside arrays unsorted.
- `key_prefix` is lowercased in `create_challenge`, and `solve_challenge` and `verify_solution` compare it case-insensitively. Before, a signed uppercase prefix never verified and made `solve_challenge` loop forever.
- On the `keySignature` fast path, a `derivedKey` that is not an even-length hex string is rejected. Before, odd-length or non-hex strings could decode to the real key and verify.
- `verify_solution` returns a result instead of raising for any malformed client input:
  - a non-numeric `counter`;
  - a `derivedKey` that is not a string or not valid UTF-8;
  - a non-numeric `expiresAt`;
  - a challenge `signature` that is not a string;
  - challenge parameters containing invalid UTF-8.
- `verify_server_signature` returns a result for an unsupported `algorithm` or a non-string `verificationData`. Before, unknown algorithms fell back to SHA-256. A non-numeric or zero `expire` never expires, as in JS.
- `verify_fields_hash` hashes falsy values (`nil`, `false`, `0`, `''`) as empty strings, as JS `String(value || '')` does.
- A `keySignature` or secret that is `''` (or another falsy value) skips the fast path and re-derives the key, as in JS.
