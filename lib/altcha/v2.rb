# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'json'
require 'time'
require 'uri'

module Altcha
  # V2 proof-of-work: find a counter C such that KDF(nonce+C) starts with keyPrefix.
  # Supports SHA-*, PBKDF2/SHA-*, and SCRYPT algorithms via OpenSSL::KDF.
  module V2
    DEFAULT_KEY_LENGTH = 32
    DEFAULT_KEY_PREFIX = '00'
    # Even-length hex string (case-insensitive, like JS parseInt).
    HEX_PATTERN = /\A(?:[0-9a-fA-F]{2})*\z/.freeze

    # All parameters embedded in a v2 challenge.
    class ChallengeParameters
      # camelCase keys backed by attributes; any other key goes to #extra.
      KEYS = %w[algorithm cost data expiresAt keyLength keyPrefix keySignature
                memoryCost nonce parallelism salt].freeze

      attr_accessor :algorithm, :nonce, :salt, :cost, :key_signature, :memory_cost,
                    :parallelism, :expires_at, :data, :extra
      attr_writer :key_length, :key_prefix

      # extra: keys from a parsed challenge with no non-nil attribute (unknown
      # fields, explicit nulls). Serialized verbatim so the signed canonical JSON
      # matches what the issuer signed, as JS canonicalJSON does.
      def initialize(algorithm:, nonce:, salt:, cost:, key_length: DEFAULT_KEY_LENGTH,
                     key_prefix: DEFAULT_KEY_PREFIX, key_signature: nil,
                     memory_cost: nil, parallelism: nil, expires_at: nil, data: nil, extra: {})
        @algorithm    = algorithm
        @nonce        = nonce
        @salt         = salt
        @cost         = cost
        @key_length   = key_length
        @key_prefix   = key_prefix
        @key_signature = key_signature
        @memory_cost  = memory_cost
        @parallelism  = parallelism
        @expires_at   = expires_at
        @data         = data
        @extra        = extra
      end

      # A parsed challenge may omit keyLength/keyPrefix: use the defaults for
      # solving and verifying, but keep them out of the signed JSON.
      def key_length
        @key_length.nil? ? DEFAULT_KEY_LENGTH : @key_length
      end

      def key_prefix
        @key_prefix.nil? ? DEFAULT_KEY_PREFIX : @key_prefix
      end

      # Serializes to a plain Hash with camelCase keys: non-nil attributes plus
      # #extra. Must reproduce the issuer's parameters exactly for HMAC signing.
      def to_h
        h = {
          'algorithm'    => algorithm,
          'cost'         => cost,
          'data'         => data,
          'expiresAt'    => expires_at,
          'keyLength'    => @key_length,
          'keyPrefix'    => @key_prefix,
          'keySignature' => key_signature,
          'memoryCost'   => memory_cost,
          'nonce'        => nonce,
          'parallelism'  => parallelism,
          'salt'         => salt
        }.compact
        extra.each { |key, value| h[key] = value unless h.key?(key) }
        h
      end

      def to_json(options = {})
        to_h.to_json(options)
      end
    end

    # A v2 challenge as returned by V2.create_challenge.
    class Challenge
      attr_accessor :parameters, :signature

      def initialize(parameters:, signature: nil)
        @parameters = parameters
        @signature  = signature
      end

      def to_h
        h = { 'parameters' => parameters.to_h }
        h['signature'] = signature unless signature.nil?
        h
      end

      def to_json(options = {})
        to_h.to_json(options)
      end

      def self.from_h(data)
        p = data['parameters']
        new(
          parameters: ChallengeParameters.new(
            algorithm:    p['algorithm'],
            nonce:        p['nonce'],
            salt:         p['salt'],
            cost:         p['cost'],
            key_length:   p['keyLength'],
            key_prefix:   p['keyPrefix'],
            key_signature: p['keySignature'],
            memory_cost:  p['memoryCost'],
            parallelism:  p['parallelism'],
            expires_at:   p['expiresAt'],
            data:         p['data'],
            extra:        p.reject { |key, value| !value.nil? && ChallengeParameters::KEYS.include?(key) }
          ),
          signature: data['signature']
        )
      end

      def self.from_json(string)
        from_h(JSON.parse(string))
      end
    end

    # The solution produced by V2.solve_challenge.
    class Solution
      attr_accessor :counter, :derived_key, :time

      def initialize(counter:, derived_key:, time: nil)
        @counter     = counter
        @derived_key = derived_key
        @time        = time
      end

      def to_h
        { 'counter' => counter, 'derivedKey' => derived_key }
      end

      def to_json(options = {})
        to_h.to_json(options)
      end
    end

    # The client payload submitted after solving a v2 challenge.
    class Payload
      attr_accessor :challenge, :solution

      def initialize(challenge:, solution:)
        @challenge = challenge
        @solution  = solution
      end

      def to_json(options = {})
        { 'challenge' => challenge.to_h, 'solution' => solution.to_h }.to_json(options)
      end

      def self.from_json(string)
        data = JSON.parse(string)
        new(
          challenge: Challenge.from_h(data['challenge']),
          solution:  Solution.new(
            counter:     data['solution']['counter'],
            derived_key: data['solution']['derivedKey']
          )
        )
      end
    end

    # Detailed result returned by V2.verify_solution.
    class VerifySolutionResult
      attr_accessor :expired, :invalid_signature, :invalid_solution, :time, :verified

      def initialize(expired:, invalid_signature:, invalid_solution:, time:, verified:)
        @expired           = expired
        @invalid_signature = invalid_signature
        @invalid_solution  = invalid_solution
        @time              = time
        @verified          = verified
      end
    end

    # Payload received from the ALTCHA backend for server-side verification.
    class ServerSignaturePayload
      attr_accessor :algorithm, :api_key, :id, :signature, :verification_data, :verified

      def initialize(algorithm:, verification_data:, signature:, verified:, api_key: nil, id: nil)
        @algorithm         = algorithm
        @api_key           = api_key
        @id                = id
        @signature         = signature
        @verification_data = verification_data
        @verified          = verified
      end

      def to_json(options = {})
        h = {
          'algorithm'        => algorithm,
          'signature'        => signature,
          'verificationData' => verification_data,
          'verified'         => verified,
        }
        h['apiKey'] = api_key unless api_key.nil?
        h['id']     = id      unless id.nil?
        h.to_json(options)
      end

      def self.from_h(data)
        new(
          algorithm:         data['algorithm'],
          api_key:           data['apiKey'],
          id:                data['id'],
          signature:         data['signature'],
          verification_data: data['verificationData'],
          verified:          data['verified']
        )
      end

      def self.from_json(string)
        from_h(JSON.parse(string))
      end

      def self.from_base64(string)
        from_json(Base64.decode64(string))
      end
    end

    # Detailed result returned by V2.verify_server_signature.
    class VerifyServerSignatureResult
      attr_accessor :expired, :invalid_signature, :invalid_solution, :time,
                    :verification_data, :verified

      def initialize(expired:, invalid_signature:, invalid_solution:, time:,
                     verification_data:, verified:)
        @expired           = expired
        @invalid_signature = invalid_signature
        @invalid_solution  = invalid_solution
        @time              = time
        @verification_data = verification_data
        @verified          = verified
      end
    end

    # Options for V2.create_challenge.
    class CreateChallengeOptions
      attr_accessor :algorithm, :cost, :counter, :counter_mode, :data, :expires_at,
                    :hmac_algorithm, :hmac_signature_secret, :hmac_key_signature_secret,
                    :key_length, :key_prefix, :key_prefix_length,
                    :memory_cost, :parallelism

      def initialize(algorithm:, cost:, counter: nil, counter_mode: 'uint32', data: nil,
                     expires_at: nil, hmac_algorithm: 'SHA-256', hmac_signature_secret: nil,
                     hmac_key_signature_secret: nil, key_length: nil, key_prefix: nil,
                     key_prefix_length: nil, memory_cost: nil, parallelism: nil)
        @algorithm                = algorithm
        @cost                     = cost
        @counter                  = counter
        @counter_mode             = counter_mode
        @data                     = data
        @expires_at               = expires_at
        @hmac_algorithm           = hmac_algorithm
        @hmac_signature_secret    = hmac_signature_secret
        @hmac_key_signature_secret = hmac_key_signature_secret
        @key_length               = key_length
        @key_prefix               = key_prefix
        @key_prefix_length        = key_prefix_length
        @memory_cost              = memory_cost
        @parallelism              = parallelism
      end
    end

    # -------------------------------------------------------------------------
    # Module-level functions
    # -------------------------------------------------------------------------

    # Largest integer a JS number holds exactly (Number.MAX_SAFE_INTEGER).
    MAX_SAFE_INTEGER = (2**53) - 1

    # Largest array index; JSON.stringify emits keys "0".."4294967294" first.
    MAX_ARRAY_INDEX = (2**32) - 2

    # Produces a canonical (sorted-key, compact) JSON string, byte-identical to
    # JS JSON.stringify(sortKeys(obj)): keys and numbers are ordered/formatted
    # like JS so signatures match across implementations and survive a JS
    # parse/stringify round-trip.
    def self.canonical_json(obj)
      js_json(obj, true)
    end

    # sort_keys mirrors JS sortKeys, which recurses into objects but returns
    # arrays (and any objects inside them) untouched.
    def self.js_json(obj, sort_keys)
      case obj
      when Hash
        pairs = js_key_order(obj, sort_keys).map { |k, v| "#{k.to_json}:#{js_json(v, sort_keys)}" }
        "{#{pairs.join(',')}}"
      when Array
        "[#{obj.map { |v| js_json(v, false) }.join(',')}]"
      when Integer, Float
        js_number(obj)
      else
        obj.to_json
      end
    end
    private_class_method :js_json

    # JS object key order: array-index keys ascending numerically, then the
    # remaining keys in insertion order. sortKeys inserts them sorted with
    # Array#sort, which compares UTF-16 code units.
    def self.js_key_order(hash, sort_keys)
      pairs = hash.map { |k, v| [k.to_s, v] }
      index_pairs, named_pairs = pairs.partition { |k, _| array_index_key?(k) }
      named_pairs = named_pairs.sort_by { |k, _| k.encode(Encoding::UTF_16BE) } if sort_keys
      index_pairs.sort_by { |k, _| k.to_i } + named_pairs
    end
    private_class_method :js_key_order

    # Invalid-UTF-8 keys (e.g. JSON-parsed lone surrogates) are never indices;
    # checking first keeps the regex from raising on them.
    def self.array_index_key?(key)
      key.valid_encoding? && /\A(?:0|[1-9][0-9]{0,9})\z/.match?(key) && key.to_i <= MAX_ARRAY_INDEX
    end
    private_class_method :array_index_key?

    # ECMAScript Number::toString as used by JSON.stringify; non-finite → null.
    # Float#to_s yields the shortest round-trip digits, same as JS.
    def self.js_number_to_s(float)
      return 'null' unless float.finite?
      return '0' if float.zero?

      mantissa, exponent = float.abs.to_s.split('e')
      int_part, frac_part = mantissa.split('.')
      all_digits = int_part + frac_part.to_s
      digits     = all_digits.sub(/\A0+/, '')
      # n: position of the decimal point relative to the first significant digit.
      n      = int_part.length + exponent.to_i - (all_digits.length - digits.length)
      digits = digits.sub(/0+\z/, '')
      k      = digits.length

      s = if k <= n && n <= 21
            digits + ('0' * (n - k))
          elsif n.positive? && n <= 21
            "#{digits[0, n]}.#{digits[n..]}"
          elsif n > -6 && n <= 0
            "0.#{'0' * -n}#{digits}"
          else
            e   = n - 1
            exp = e.negative? ? "e-#{-e}" : "e+#{e}"
            k == 1 ? "#{digits}#{exp}" : "#{digits[0]}.#{digits[1..]}#{exp}"
          end
      float.negative? ? "-#{s}" : s
    end
    private_class_method :js_number_to_s

    # JS Number#toString for a JSON-number value (Integer or finite Float).
    def self.js_number(num)
      num.is_a?(Integer) && num.abs <= MAX_SAFE_INTEGER ? num.to_s : js_number_to_s(num.to_f)
    end
    private_class_method :js_number

    # Counter encodings supported by altcha-lib (JS PasswordBuffer).
    COUNTER_MODES = %w[uint32 string].freeze

    # Builds the password buffer (nonce bytes + counter) used for key derivation.
    # 'uint32': 4-byte big-endian unsigned integer (wraps mod 2^32 like JS setUint32).
    # 'string': the counter's decimal string (JS n.toString()), UTF-8 encoded.
    def self.make_password(nonce_bytes, counter, counter_mode = 'uint32')
      validate_counter_mode(counter_mode)
      nonce_bytes + (counter_mode == 'string' ? js_number(counter) : [counter].pack('N'))
    end

    def self.validate_counter_mode(counter_mode)
      return if COUNTER_MODES.include?(counter_mode)

      raise ArgumentError, "Unsupported counter mode: #{counter_mode.inspect} (expected #{COUNTER_MODES.join(', ')})"
    end
    private_class_method :validate_counter_mode

    # Derives a key from the given parameters, salt, and password bytes.
    def self.derive_key(parameters, salt_bytes, password_bytes)
      alg     = parameters.algorithm
      key_len = parameters.key_length || DEFAULT_KEY_LENGTH

      case alg
      when 'ARGON2ID'
        begin
          require 'argon2/kdf'
        rescue LoadError
          raise LoadError, "Add 'argon2-kdf' to your Gemfile to use the ARGON2ID algorithm"
        end
        memory_cost = parameters.memory_cost
        raise ArgumentError, 'ARGON2ID requires memory_cost (KiB)' if memory_cost.nil?

        # argon2-kdf's public API takes log2(memory), which cannot express
        # non-power-of-two memoryCost values, so call its libargon2 binding
        # directly with the exact KiB value (as node crypto.argon2 does).
        hash   = Fiddle::Pointer.malloc(key_len, Fiddle::RUBY_FREE)
        status = Argon2::KDF::FFI.argon2id_hash_raw(
          parameters.cost, memory_cost, parameters.parallelism || 1,
          Fiddle::Pointer[password_bytes], password_bytes.bytesize,
          Fiddle::Pointer[salt_bytes], salt_bytes.bytesize,
          hash, key_len
        )
        raise Argon2::KDF::Error, Argon2::KDF::FFI.argon2_error_message(status).to_s unless status.zero?

        hash[0, key_len]
      when /\APBKDF2\//
        digest = case alg
                 when 'PBKDF2/SHA-512' then 'SHA512'
                 when 'PBKDF2/SHA-384' then 'SHA384'
                 else 'SHA256'
                 end
        OpenSSL::KDF.pbkdf2_hmac(
          password_bytes,
          salt:       salt_bytes,
          iterations: parameters.cost,
          length:     key_len,
          hash:       digest
        )
      when 'SCRYPT'
        OpenSSL::KDF.scrypt(
          password_bytes,
          salt:   salt_bytes,
          N:      parameters.cost,
          r:      parameters.memory_cost || 8,
          p:      parameters.parallelism || 1,
          length: key_len
        )
      else
        # SHA-256 / SHA-384 / SHA-512 (iterative)
        digest     = case alg
                     when 'SHA-512' then 'SHA512'
                     when 'SHA-384' then 'SHA384'
                     else 'SHA256'
                     end
        iterations = [parameters.cost, 1].max
        buf        = salt_bytes.b + password_bytes.b
        derived    = nil
        iterations.times do |i|
          derived = OpenSSL::Digest.digest(digest, i.zero? ? buf : derived)
        end
        derived[0, key_len]
      end
    end

    # HMAC algorithms supported by altcha-lib (JS HmacAlgorithm) → OpenSSL digest.
    HMAC_DIGESTS = { 'SHA-256' => 'SHA256', 'SHA-384' => 'SHA384', 'SHA-512' => 'SHA512' }.freeze

    # Computes an HMAC hex digest using the specified algorithm ('SHA-256' etc.).
    # Raises ArgumentError for any algorithm outside HMAC_DIGESTS.
    def self.hmac_hex(data, key, algorithm = 'SHA-256')
      OpenSSL::HMAC.hexdigest(hmac_digest(algorithm), key, data)
    end

    def self.hmac_digest(algorithm)
      HMAC_DIGESTS.fetch(algorithm) do
        raise ArgumentError, "Unsupported HMAC algorithm: #{algorithm.inspect} (expected #{HMAC_DIGESTS.keys.join(', ')})"
      end
    end
    private_class_method :hmac_digest

    # Constant-time string comparison.
    def self.constant_time_equal?(a, b)
      return false if a.bytesize != b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    rescue ArgumentError
      false
    end

    # Creates a v2 proof-of-work challenge.
    # @param options [CreateChallengeOptions]
    # @return [Challenge]
    def self.create_challenge(options)
      hmac_digest(options.hmac_algorithm) # raise early, even for unsigned challenges
      validate_counter_mode(options.counter_mode)
      key_length        = options.key_length        || DEFAULT_KEY_LENGTH
      key_prefix        = (options.key_prefix       || DEFAULT_KEY_PREFIX).downcase
      key_prefix_length = options.key_prefix_length || (key_length / 2)
      expires_at        = options.expires_at.is_a?(Time) ? options.expires_at.to_i : options.expires_at

      parameters = ChallengeParameters.new(
        algorithm:   options.algorithm,
        nonce:       OpenSSL::Random.random_bytes(16).unpack1('H*'),
        salt:        OpenSSL::Random.random_bytes(16).unpack1('H*'),
        cost:        options.cost,
        key_length:  key_length,
        key_prefix:  key_prefix,
        memory_cost: options.memory_cost,
        parallelism: options.parallelism,
        expires_at:  expires_at,
        data:        options.data
      )

      derived_key_bytes = nil

      if options.counter
        nonce_bytes       = [parameters.nonce].pack('H*')
        salt_bytes        = [parameters.salt].pack('H*')
        password_bytes    = make_password(nonce_bytes, options.counter, options.counter_mode)
        derived_key_bytes = derive_key(parameters, salt_bytes, password_bytes)
        parameters.key_prefix = derived_key_bytes[0, key_prefix_length].unpack1('H*')
      end

      if present?(options.hmac_signature_secret)
        if derived_key_bytes && present?(options.hmac_key_signature_secret)
          parameters.key_signature = hmac_hex(
            derived_key_bytes,
            options.hmac_key_signature_secret,
            options.hmac_algorithm
          )
        end
        signature = hmac_hex(
          canonical_json(parameters.to_h),
          options.hmac_signature_secret,
          options.hmac_algorithm
        )
        Challenge.new(parameters: parameters, signature: signature)
      else
        Challenge.new(parameters: parameters)
      end
    end

    # Solves a v2 challenge by brute-forcing counter values.
    # @param challenge [Challenge]
    # @param max_counter [Integer, nil] Safety cap; nil means no limit.
    # @param counter_start [Integer]
    # @param counter_step [Integer]
    # @param counter_mode [String] 'uint32' (default) or 'string'; must match create_challenge.
    # @return [Solution, nil]
    def self.solve_challenge(challenge, max_counter: nil, counter_start: 0, counter_step: 1,
                             counter_mode: 'uint32')
      validate_counter_mode(counter_mode)
      parameters  = challenge.parameters
      nonce_bytes = [parameters.nonce].pack('H*')
      salt_bytes  = [parameters.salt].pack('H*')
      # Derived keys are lowercase hex; match prefixes case-insensitively.
      key_prefix  = parameters.key_prefix.downcase
      start_time  = Time.now
      counter     = counter_start

      loop do
        return nil if max_counter && counter > max_counter

        password_bytes    = make_password(nonce_bytes, counter, counter_mode)
        derived_key_bytes = derive_key(parameters, salt_bytes, password_bytes)
        derived_key_hex   = derived_key_bytes.unpack1('H*')

        if derived_key_hex.start_with?(key_prefix)
          return Solution.new(
            counter:     counter,
            derived_key: derived_key_hex,
            time:        ((Time.now - start_time) * 1000).round
          )
        end

        counter += counter_step
      end
    end

    # Verifies a v2 solution against its challenge.
    # @param challenge [Challenge]
    # @param solution [Solution]
    # @param hmac_signature_secret [String] Must match what was used in create_challenge.
    # @param hmac_key_signature_secret [String, nil] Required when keySignature is present.
    # @param hmac_algorithm [String] Defaults to 'SHA-256'.
    # @param counter_mode [String] 'uint32' (default) or 'string'; must match create_challenge.
    # @return [VerifySolutionResult]
    def self.verify_solution(challenge, solution, hmac_signature_secret:,
                             hmac_key_signature_secret: nil,
                             hmac_algorithm: 'SHA-256', counter_mode: 'uint32')
      start_time = Time.now
      hmac_digest(hmac_algorithm) # raise on misconfiguration, before any early return
      validate_counter_mode(counter_mode)
      # An empty secret makes signatures forgeable (JS WebCrypto rejects it too).
      raise ArgumentError, 'hmac_signature_secret must be a non-empty String' unless present?(hmac_signature_secret)

      # 1. Expiration check. Runs before the signature check, so expires_at may
      # be tampered: only numbers are compared; anything else falls through and
      # fails the signature check. Like JS `expiresAt && expiresAt < now`:
      # 0 means no expiry, and now keeps fractional seconds (no 1 s grace).
      expires_at = challenge.parameters.expires_at
      if (expires_at.is_a?(Integer) || expires_at.is_a?(Float)) &&
         !expires_at.zero? && expires_at < Time.now.to_f
        return VerifySolutionResult.new(
          expired: true, invalid_signature: nil, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 2. Signature presence check. The signature is client input: anything
      # but a String (e.g. 123, an Array) is invalid instead of raising.
      unless challenge.signature.is_a?(String)
        return VerifySolutionResult.new(
          expired: false, invalid_signature: true, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 3. Verify challenge signature (tamper detection). The parameters are
      # client input: strings that cannot be serialized (invalid UTF-8, e.g. a
      # JSON-parsed lone surrogate) cannot match any signature we issued.
      begin
        signed_json = canonical_json(challenge.parameters.to_h)
      rescue JSON::GeneratorError, EncodingError
        return VerifySolutionResult.new(
          expired: false, invalid_signature: true, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end
      expected_sig = hmac_hex(signed_json, hmac_signature_secret, hmac_algorithm)
      unless constant_time_equal?(challenge.signature, expected_sig)
        return VerifySolutionResult.new(
          expired: false, invalid_signature: true, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # The solution is unsigned client input: reject malformed fields instead
      # of raising. Counter must be a JSON number (wrapped mod 2^32 like JS
      # DataView.setUint32); derived_key must be a string.
      unless valid_solution_fields?(solution)
        return VerifySolutionResult.new(
          expired: false, invalid_signature: false, invalid_solution: true,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 4a. Fast path: verify via key signature when available.
      # pack('H*') never fails: it pads odd lengths and maps non-hex characters
      # to nibbles, so only well-formed hex is decoded.
      if present?(challenge.parameters.key_signature) && present?(hmac_key_signature_secret)
        valid = HEX_PATTERN.match?(solution.derived_key) &&
                constant_time_equal?(
                  challenge.parameters.key_signature,
                  hmac_hex([solution.derived_key].pack('H*'), hmac_key_signature_secret, hmac_algorithm)
                )
        return VerifySolutionResult.new(
          expired: false, invalid_signature: false, invalid_solution: !valid,
          time: elapsed_ms(start_time), verified: valid
        )
      end

      # 4b. Slow path: re-derive key from the submitted counter and compare,
      # and require it to satisfy the signed key prefix.
      nonce_bytes       = [challenge.parameters.nonce].pack('H*')
      salt_bytes        = [challenge.parameters.salt].pack('H*')
      password_bytes    = make_password(nonce_bytes, solution.counter, counter_mode)
      derived_key_bytes = derive_key(challenge.parameters, salt_bytes, password_bytes)
      derived_key_hex   = derived_key_bytes.unpack1('H*')
      key_matches       = constant_time_equal?(derived_key_hex, solution.derived_key)
      prefix_matches    = derived_key_hex.start_with?(challenge.parameters.key_prefix.downcase)
      invalid           = !(key_matches && prefix_matches)

      VerifySolutionResult.new(
        expired: false, invalid_signature: false, invalid_solution: invalid,
        time: elapsed_ms(start_time), verified: !invalid
      )
    end

    # Parses a URL-encoded verification_data string into a typed Hash.
    # Booleans, integers, and floats are auto-detected; comma-separated fields
    # listed in +array_fields+ are converted to arrays.
    def self.parse_verification_data(data, array_fields: %w[fields reasons])
      result = {}
      URI.decode_www_form(data).each do |key, value|
        result[key] = if value == 'true'
                        true
                      elsif value == 'false'
                        false
                      elsif /\A\d+\z/.match?(value)
                        value.to_i
                      elsif /\A\d+\.\d+\z/.match?(value)
                        value.to_f
                      elsif array_fields.include?(key) && !value.empty?
                        value.strip.split(',')
                      else
                        value.strip
                      end
      end
      result
    rescue StandardError
      nil
    end

    # Verifies the SHA hash of selected form fields.
    # @param form_data [Hash]
    # @param fields [Array<String>]
    # @param fields_hash [String] Expected hex digest.
    # @param algorithm [String] Defaults to 'SHA-256'.
    # @return [Boolean]
    def self.verify_fields_hash(form_data:, fields:, fields_hash:, algorithm: 'SHA-256')
      digest = case algorithm
               when 'SHA-512' then 'SHA512'
               when 'SHA-384' then 'SHA384'
               else 'SHA256'
               end
      lines = fields.map { |f| form_data[f].to_s }
      OpenSSL::Digest.hexdigest(digest, lines.join("\n")) == fields_hash
    end

    # Verifies a server signature payload from the ALTCHA backend.
    # @param payload [ServerSignaturePayload]
    # @param hmac_secret [String]
    # @return [VerifyServerSignatureResult]
    def self.verify_server_signature(payload:, hmac_secret:)
      start_time = Time.now

      # The payload is client input: an unsupported algorithm or non-String
      # verification_data fails the signature check instead of raising.
      digest = HMAC_DIGESTS[payload.algorithm] if payload.verification_data.is_a?(String)
      expected_sig = if digest
                       hmac_hex(OpenSSL::Digest.digest(digest, payload.verification_data), hmac_secret, payload.algorithm)
                     end
      verification_data = parse_verification_data(payload.verification_data)

      # Like JS `!!expire && expire < now`: non-numeric or 0 never expires.
      expire  = verification_data && verification_data['expire']
      expired = (expire.is_a?(Integer) || expire.is_a?(Float)) && !expire.zero? && expire < Time.now.to_i

      invalid_signature = expected_sig.nil? || !constant_time_equal?(payload.signature.to_s, expected_sig)

      invalid_solution = verification_data.nil? ||
                         verification_data['verified'] != true ||
                         payload.verified != true

      verified = !expired && !invalid_signature && !invalid_solution

      VerifyServerSignatureResult.new(
        expired:           expired,
        invalid_signature: invalid_signature,
        invalid_solution:  invalid_solution,
        time:              elapsed_ms(start_time),
        verification_data: verification_data,
        verified:          verified
      )
    end

    def self.elapsed_ms(start_time)
      ((Time.now - start_time) * 1000).round
    end

    # derived_key must be a validly encoded String: the 4a hex regex raises on
    # invalid UTF-8, and such a key can never match a hex key in 4b.
    def self.valid_solution_fields?(solution)
      counter     = solution.counter
      derived_key = solution.derived_key
      (counter.is_a?(Integer) || (counter.is_a?(Float) && counter.finite?)) &&
        derived_key.is_a?(String) && derived_key.valid_encoding?
    end
    private_class_method :valid_solution_fields?

    # JS truthiness for optional secrets/signatures: nil, false and '' are unset.
    def self.present?(value)
      !(value.nil? || value == false || value == '')
    end
    private_class_method :present?
    private_class_method :elapsed_ms
  end
end
