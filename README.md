# ALTCHA Ruby Library

The ALTCHA Ruby Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges. It supports both the current **PoW v2** protocol and the legacy **PoW v1** protocol.

## Compatibility

- Ruby 2.7+

## Examples

- [`examples/server.rb`](/examples/server.rb)

## Installation

Add to your Gemfile:

```ruby
gem 'altcha'
```

Then run:

```sh
bundle install
```

Or install directly:

```sh
gem install altcha
```

## Optional dependencies

| Algorithm | Gem | System library |
|---|---|---|
| `ARGON2ID` | [`argon2-kdf`](https://github.com/ankane/argon2-kdf) | `libargon2` |

The `argon2-kdf` gem is only required if you use the `ARGON2ID` algorithm. Add it to your Gemfile when needed:

```ruby
gem 'argon2-kdf'
```

A `LoadError` with an actionable message is raised at runtime if the gem is missing and `ARGON2ID` is requested.

## Usage

### PoW v2 (current)

```ruby
require 'altcha'
require 'securerandom'

hmac_secret = 'secret hmac key'

# Create a challenge
options = Altcha::V2::CreateChallengeOptions.new(
  algorithm: 'PBKDF2/SHA-256',
  cost: 5_000,
  counter: SecureRandom.random_number(5_000..10_000),
  hmac_signature_secret: hmac_secret
)

challenge = Altcha::V2.create_challenge(options)
# => #<Altcha::V2::Challenge ...>

# Solve (client-side)
solution = Altcha::V2.solve_challenge(challenge)
# => #<Altcha::V2::Solution counter=..., derived_key="...">

# Verify (server-side)
result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
puts result.verified ? "Verified!" : "Invalid solution."
```

The payload sent from the client to the server is a JSON object:

```ruby
payload = Altcha::V2::Payload.new(challenge: challenge, solution: solution)
json    = payload.to_json  # send this to the server

# Server-side: restore and verify
restored = Altcha::V2::Payload.from_json(json)
result   = Altcha::V2.verify_solution(
  restored.challenge,
  restored.solution,
  hmac_signature_secret: hmac_secret
)
```

### PoW v1 (legacy)

```ruby
require 'altcha'

hmac_key = 'secret hmac key'

# Create a challenge
options = Altcha::V1::ChallengeOptions.new(
  hmac_key: hmac_key,
  max_number: 100_000
)

challenge = Altcha::V1.create_challenge(options)

# Verify a solution submitted by the client
valid = Altcha::V1.verify_solution(payload, hmac_key, true)
puts valid ? "Verified!" : "Invalid solution."
```

## V2 API

### `Altcha::V2.create_challenge(options)` → `Challenge`

Creates a new v2 challenge.

**`CreateChallengeOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `String` | — | Key derivation algorithm: `SHA-256`, `SHA-384`, `SHA-512`, `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`, `SCRYPT`, `ARGON2ID`. |
| `cost` | `Integer` | — | Algorithm cost (iterations for PBKDF2/SHA, N for SCRYPT). |
| `counter` | `Integer` | `nil` | Pre-compute a deterministic key prefix from this counter value. |
| `data` | `Hash` | `nil` | Arbitrary metadata to embed in the challenge. |
| `expires_at` | `Integer, Time` | `nil` | Expiration timestamp (Unix seconds or `Time`). |
| `hmac_signature_secret` | `String` | `nil` | Signs the challenge parameters. Required for `verify_solution`. |
| `hmac_key_signature_secret` | `String` | `nil` | Signs the derived key (fast-path verification). Requires `counter`. |
| `key_length` | `Integer` | `32` | Derived key length in bytes. |
| `key_prefix` | `String` | `'00'` | Hex prefix the derived key must start with. |
| `key_prefix_length` | `Integer` | `key_length / 2` | Bytes of the derived key used as prefix in deterministic mode. |
| `memory_cost` | `Integer` | `nil` | Memory cost in KiB (`ARGON2ID`), or block size `r` (`SCRYPT`). |
| `parallelism` | `Integer` | `nil` | Parallelism factor (`ARGON2ID`, `SCRYPT`). |

---

### `Altcha::V2.solve_challenge(challenge, ...)` → `Solution, nil`

Solves a challenge by iterating counter values until the derived key starts with `key_prefix`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `challenge` | `Challenge` | — | Challenge to solve. |
| `max_counter` | `Integer, nil` | `nil` | Safety cap on the counter. Returns `nil` if exceeded. |
| `counter_start` | `Integer` | `0` | Starting counter value. |
| `counter_step` | `Integer` | `1` | Counter increment per iteration. |

---

### `Altcha::V2.verify_solution(challenge, solution, ...)` → `VerifySolutionResult`

Verifies a submitted solution.

| Parameter | Type | Description |
|---|---|---|
| `challenge` | `Challenge` | The original challenge. |
| `solution` | `Solution` | The submitted solution. |
| `hmac_signature_secret:` | `String` | Must match the secret used in `create_challenge`. |
| `hmac_key_signature_secret:` | `String, nil` | Required when `key_signature` is present. |
| `hmac_algorithm:` | `String` | HMAC digest algorithm (`SHA-256`, `SHA-384`, `SHA-512`). Default: `SHA-256`. |

**`VerifySolutionResult`**

| Field | Type | Description |
|---|---|---|
| `verified` | `Boolean` | `true` if the solution is valid. |
| `expired` | `Boolean` | `true` if the challenge has expired. |
| `invalid_signature` | `Boolean, nil` | `true` if the challenge signature is missing or wrong. |
| `invalid_solution` | `Boolean, nil` | `true` if the derived key does not match. |
| `time` | `Integer` | Verification time in milliseconds. |

---

### `Altcha::V2.verify_server_signature(payload:, hmac_secret:)` → `VerifyServerSignatureResult`

Verifies a server signature payload issued by the ALTCHA backend.

| Parameter | Type | Description |
|---|---|---|
| `payload:` | `ServerSignaturePayload` | Decoded payload from the ALTCHA backend. |
| `hmac_secret:` | `String` | Shared secret used to sign the payload. |

**`VerifyServerSignatureResult`**

| Field | Type | Description |
|---|---|---|
| `verified` | `Boolean` | `true` if the payload is valid and unexpired. |
| `expired` | `Boolean` | `true` if `expire` is in the past. |
| `invalid_signature` | `Boolean` | `true` if the HMAC signature does not match. |
| `invalid_solution` | `Boolean` | `true` if `verified` is not `true` in the payload or verification data. |
| `verification_data` | `Hash, nil` | Parsed verification data with auto-typed values. |
| `time` | `Integer` | Verification time in milliseconds. |

---

### `Altcha::V2.verify_fields_hash(form_data:, fields:, fields_hash:, algorithm: 'SHA-256')` → `Boolean`

Verifies the SHA digest of selected form fields, matching the `fieldsHash` included in `verification_data`.

---

### `Altcha::V2.parse_verification_data(data)` → `Hash, nil`

Parses a URL-encoded `verificationData` string into a typed Hash. Booleans, integers, and floats are auto-detected; `fields` and `reasons` are converted to arrays.

---

### `Altcha::V2.canonical_json(obj)` → `String`

Produces a canonical (alphabetically sorted keys, compact) JSON string. Used internally for signing.

---

### Data classes

**`Altcha::V2::Challenge`** — challenge sent to the client.
- `parameters` — `ChallengeParameters`
- `signature` — `String, nil`
- `.from_json(string)` / `#to_json`

**`Altcha::V2::ChallengeParameters`** — all parameters embedded in a challenge.

**`Altcha::V2::Solution`** — solution returned by `solve_challenge`.
- `counter` — `Integer`
- `derived_key` — `String` (hex)
- `time` — `Integer, nil` (milliseconds)

**`Altcha::V2::Payload`** — combined challenge + solution for client→server transport.
- `.from_json(string)` / `#to_json`

**`Altcha::V2::ServerSignaturePayload`** — payload from the ALTCHA backend signature verification.
- `algorithm`, `verification_data`, `signature`, `verified`, `api_key`, `id`
- `.from_json(string)` / `.from_base64(string)` / `#to_json`

---

## V1 API (legacy)

### `Altcha::V1.create_challenge(options)` → `Challenge`

| Option | Type | Default | Description |
|---|---|---|---|
| `hmac_key` | `String` | — | Required HMAC key. |
| `algorithm` | `String` | `SHA-256` | Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`). |
| `max_number` | `Integer` | `1_000_000` | Upper bound for the random number. |
| `salt_length` | `Integer` | `12` | Random salt length in bytes. |
| `salt` | `String` | `nil` | Override generated salt. |
| `number` | `Integer` | `nil` | Override random number. |
| `expires` | `Time` | `nil` | Challenge expiration time. |
| `params` | `Hash` | `nil` | Extra URL-encoded parameters embedded in the salt. |

### `Altcha::V1.verify_solution(payload, hmac_key, check_expires = true)` → `Boolean`

### `Altcha::V1.verify_fields_hash(form_data, fields, fields_hash, algorithm)` → `Boolean`

### `Altcha::V1.verify_server_signature(payload, hmac_key)` → `[Boolean, ServerSignatureVerificationData]`

### `Altcha::V1.solve_challenge(challenge, salt, algorithm, max, start)` → `Solution, nil`

### `Altcha::V1.extract_params(payload)` → `Hash`

## License

MIT
