# ALTCHA Ruby Library

The ALTCHA Ruby Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

This library is compatible with:

- Ruby 2.7+

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-rb)

## Installation

To install the ALTCHA Ruby Library, add it to your Gemfile:

```ruby
gem 'altcha', git: 'https://github.com/altcha-org/altcha-lib-rb'
```

Then run:

```sh
bundle install
```

Alternatively, install it directly using:

```sh
gem install altcha
```

## Usage

Here’s a basic example of how to use the ALTCHA Ruby Library:

```ruby
require 'altcha'

hmac_key = 'secret hmac key'

# Create a new challenge
options = Altcha::ChallengeOptions.new.tap do |opts|
  opts.hmac_key = hmac_key
  opts.max_number = 100000 # the maximum random number
end

challenge = Altcha.create_challenge(options)

# Example payload to verify
payload = {
  algorithm: challenge.algorithm,
  challenge: challenge.challenge,
  number: 12345, # Example number
  salt: challenge.salt,
  signature: challenge.signature
}

# Verify the solution
valid = Altcha.verify_solution(payload, hmac_key, true)
puts valid ? "Solution verified!" : "Invalid solution."
```

## API

### `Altcha.create_challenge(options)`

Creates a new challenge for ALTCHA.

**Parameters:**

- `options [ChallengeOptions]`:
  - `algorithm [String]`: Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default: `SHA-256`).
  - `max_number [Integer]`: Maximum number for the random number generator (default: 1,000,000).
  - `salt_length [Integer]`: Length of the random salt (default: 12 bytes).
  - `hmac_key [String]`: Required HMAC key.
  - `salt [String]`: Optional salt string. If not provided, a random salt will be generated.
  - `number [Integer]`: Optional specific number to use. If not provided, a random number will be generated.
  - `expires [Time]`: Optional expiration time for the challenge.
  - `params [Hash]`: Optional URL-encoded query parameters.

**Returns:** `Challenge`

### `Altcha.verify_solution(payload, hmac_key, check_expires = true)`

Verifies an ALTCHA solution.

**Parameters:**

- `payload [Hash]`: The solution payload to verify.
- `hmac_key [String]`: The HMAC key used for verification.
- `check_expires [Boolean]`: Whether to check if the challenge has expired.

**Returns:** `Boolean`

### `Altcha.extract_params(payload)`

Extracts URL parameters from the payload's salt.

**Parameters:**

- `payload [Hash]`: The payload containing the salt.

**Returns:** `Hash`

### `Altcha.verify_fields_hash(form_data, fields, fields_hash, algorithm)`

Verifies the hash of form fields.

**Parameters:**

- `form_data [Hash]`: The form data to hash.
- `fields [Array<String>]`: The fields to include in the hash.
- `fields_hash [String]`: The expected hash value.
- `algorithm [String]`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).

**Returns:** `Boolean`

### `Altcha.verify_server_signature(payload, hmac_key)`

Verifies the server's signature.

**Parameters:**

- `payload [String, ServerSignaturePayload]`: The payload to verify (string or `ServerSignaturePayload`).
- `hmac_key [String]`: The HMAC key used for verification.

**Returns:** `[Boolean, ServerSignatureVerificationData]`

### `Altcha.solve_challenge(challenge, salt, algorithm, max, start)`

Finds a solution to the given challenge.

**Parameters:**

- `challenge [String]`: The challenge hash.
- `salt [String]`: The challenge salt.
- `algorithm [String]`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
- `max [Integer]`: Maximum number to iterate to.
- `start [Integer]`: Starting number.

**Returns:** `Solution, nil`

## License

MIT