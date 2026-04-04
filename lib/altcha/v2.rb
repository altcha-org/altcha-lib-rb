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

    # All parameters embedded in a v2 challenge.
    class ChallengeParameters
      attr_accessor :algorithm, :nonce, :salt, :cost, :key_length, :key_prefix,
                    :key_signature, :memory_cost, :parallelism, :expires_at, :data

      def initialize(algorithm:, nonce:, salt:, cost:, key_length: DEFAULT_KEY_LENGTH,
                     key_prefix: DEFAULT_KEY_PREFIX, key_signature: nil,
                     memory_cost: nil, parallelism: nil, expires_at: nil, data: nil)
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
      end

      # Serializes to a plain Hash with camelCase keys, omitting nil optional fields.
      # The resulting hash must be stable across round-trips for HMAC signing to work.
      def to_h
        h = {
          'algorithm' => algorithm,
          'cost'      => cost,
          'keyLength' => key_length,
          'keyPrefix' => key_prefix,
          'nonce'     => nonce,
          'salt'      => salt,
        }
        h['data']         = data          unless data.nil?
        h['expiresAt']    = expires_at    unless expires_at.nil?
        h['keySignature'] = key_signature unless key_signature.nil?
        h['memoryCost']   = memory_cost   unless memory_cost.nil?
        h['parallelism']  = parallelism   unless parallelism.nil?
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
            key_length:   p.fetch('keyLength',  DEFAULT_KEY_LENGTH),
            key_prefix:   p.fetch('keyPrefix',  DEFAULT_KEY_PREFIX),
            key_signature: p['keySignature'],
            memory_cost:  p['memoryCost'],
            parallelism:  p['parallelism'],
            expires_at:   p['expiresAt'],
            data:         p['data']
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
      attr_accessor :algorithm, :cost, :counter, :data, :expires_at,
                    :hmac_signature_secret, :hmac_key_signature_secret,
                    :key_length, :key_prefix, :key_prefix_length,
                    :memory_cost, :parallelism

      def initialize(algorithm:, cost:, counter: nil, data: nil,
                     expires_at: nil, hmac_signature_secret: nil,
                     hmac_key_signature_secret: nil, key_length: nil, key_prefix: nil,
                     key_prefix_length: nil, memory_cost: nil, parallelism: nil)
        @algorithm                = algorithm
        @cost                     = cost
        @counter                  = counter
        @data                     = data
        @expires_at               = expires_at
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

    # Produces a canonical (sorted-key, compact) JSON string.
    def self.canonical_json(obj)
      case obj
      when Hash
        pairs = obj.sort_by { |k, _| k.to_s }
                   .map { |k, v| "#{k.to_s.to_json}:#{canonical_json(v)}" }
        "{#{pairs.join(',')}}"
      when Array
        "[#{obj.map { |v| canonical_json(v) }.join(',')}]"
      else
        obj.to_json
      end
    end

    # Builds the password buffer (nonce bytes + counter) used for key derivation.
    # Counter is encoded as a 4-byte big-endian unsigned integer.
    def self.make_password(nonce_bytes, counter)
      nonce_bytes + [counter].pack('N')
    end

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
        # argon2-kdf's `m` is log2(memory_cost_in_KiB) — convert from KiB.
        m_kib = parameters.memory_cost || 65536
        Argon2::KDF.argon2id(
          password_bytes,
          salt:   salt_bytes,
          t:      parameters.cost,
          m:      Math.log2(m_kib).round,
          p:      parameters.parallelism || 1,
          length: key_len
        )
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

    # Computes an HMAC hex digest using the specified algorithm ('SHA-256' etc.).
    def self.hmac_hex(data, key, algorithm = 'SHA-256')
      digest = case algorithm
               when 'SHA-384' then 'SHA384'
               when 'SHA-512' then 'SHA512'
               else 'SHA256'
               end
      OpenSSL::HMAC.hexdigest(digest, key, data)
    end

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
      key_length        = options.key_length        || DEFAULT_KEY_LENGTH
      key_prefix        = options.key_prefix        || DEFAULT_KEY_PREFIX
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
        password_bytes    = make_password(nonce_bytes, options.counter)
        derived_key_bytes = derive_key(parameters, salt_bytes, password_bytes)
        parameters.key_prefix = derived_key_bytes[0, key_prefix_length].unpack1('H*')
      end

      if options.hmac_signature_secret
        if derived_key_bytes && options.hmac_key_signature_secret
          parameters.key_signature = hmac_hex(
            derived_key_bytes,
            options.hmac_key_signature_secret
          )
        end
        signature = hmac_hex(
          canonical_json(parameters.to_h),
          options.hmac_signature_secret
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
    # @return [Solution, nil]
    def self.solve_challenge(challenge, max_counter: nil, counter_start: 0, counter_step: 1)
      parameters  = challenge.parameters
      nonce_bytes = [parameters.nonce].pack('H*')
      salt_bytes  = [parameters.salt].pack('H*')
      key_prefix  = parameters.key_prefix
      start_time  = Time.now
      counter     = counter_start

      loop do
        return nil if max_counter && counter > max_counter

        password_bytes    = make_password(nonce_bytes, counter)
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
    # @return [VerifySolutionResult]
    def self.verify_solution(challenge, solution, hmac_signature_secret:,
                             hmac_key_signature_secret: nil,
                             hmac_algorithm: 'SHA-256')
      start_time = Time.now

      # 1. Expiration check.
      if challenge.parameters.expires_at && Time.now.to_i > challenge.parameters.expires_at
        return VerifySolutionResult.new(
          expired: true, invalid_signature: nil, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 2. Signature presence check.
      unless challenge.signature
        return VerifySolutionResult.new(
          expired: false, invalid_signature: true, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 3. Verify challenge signature (tamper detection).
      expected_sig = hmac_hex(
        canonical_json(challenge.parameters.to_h),
        hmac_signature_secret,
        hmac_algorithm
      )
      unless constant_time_equal?(challenge.signature, expected_sig)
        return VerifySolutionResult.new(
          expired: false, invalid_signature: true, invalid_solution: nil,
          time: elapsed_ms(start_time), verified: false
        )
      end

      # 4a. Fast path: verify via key signature when available.
      if challenge.parameters.key_signature && hmac_key_signature_secret
        derived_key_bytes = [solution.derived_key].pack('H*')
        expected_key_sig  = hmac_hex(derived_key_bytes, hmac_key_signature_secret, hmac_algorithm)
        valid = constant_time_equal?(challenge.parameters.key_signature, expected_key_sig)
        return VerifySolutionResult.new(
          expired: false, invalid_signature: false, invalid_solution: !valid,
          time: elapsed_ms(start_time), verified: valid
        )
      end

      # 4b. Slow path: re-derive key from the submitted counter and compare.
      nonce_bytes       = [challenge.parameters.nonce].pack('H*')
      salt_bytes        = [challenge.parameters.salt].pack('H*')
      password_bytes    = make_password(nonce_bytes, solution.counter)
      derived_key_bytes = derive_key(challenge.parameters, salt_bytes, password_bytes)
      derived_key_hex   = derived_key_bytes.unpack1('H*')
      invalid           = !constant_time_equal?(derived_key_hex, solution.derived_key)

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

      digest = case payload.algorithm
               when 'SHA-512' then 'SHA512'
               when 'SHA-384' then 'SHA384'
               else 'SHA256'
               end

      hash_bytes        = OpenSSL::Digest.digest(digest, payload.verification_data)
      expected_sig      = hmac_hex(hash_bytes, hmac_secret, payload.algorithm)
      verification_data = parse_verification_data(payload.verification_data)

      expired = !!(verification_data &&
                   verification_data['expire'] &&
                   verification_data['expire'] < Time.now.to_i)

      invalid_signature = !constant_time_equal?(payload.signature.to_s, expected_sig)

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
    private_class_method :elapsed_ms
  end
end
