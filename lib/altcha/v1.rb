# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'json'
require 'uri'
require 'time'

module Altcha
  # V1 proof-of-work: find a number N such that SHA256(salt+N) equals the challenge hash.
  module V1
    # Contains algorithm type definitions for hashing.
    module Algorithm
      SHA1   = 'SHA-1'
      SHA256 = 'SHA-256'
      SHA512 = 'SHA-512'
    end

    DEFAULT_MAX_NUMBER  = 1_000_000
    DEFAULT_SALT_LENGTH = 12
    DEFAULT_ALGORITHM   = Algorithm::SHA256

    # Options for generating a challenge.
    class ChallengeOptions
      attr_accessor :algorithm, :max_number, :salt_length, :hmac_key, :salt, :number, :expires, :params

      def initialize(algorithm: nil, max_number: nil, salt_length: nil, hmac_key:,
                     salt: nil, number: nil, expires: nil, params: nil)
        @algorithm   = algorithm
        @max_number  = max_number
        @salt_length = salt_length
        @hmac_key    = hmac_key
        @salt        = salt
        @number      = number
        @expires     = expires
        @params      = params
      end
    end

    # A challenge sent to the client.
    class Challenge
      attr_accessor :algorithm, :challenge, :maxnumber, :salt, :signature

      def initialize(algorithm:, challenge:, maxnumber: nil, salt:, signature:)
        @algorithm = algorithm
        @challenge = challenge
        @maxnumber = maxnumber
        @salt      = salt
        @signature = signature
      end

      def to_json(options = {})
        {
          algorithm: @algorithm,
          challenge: @challenge,
          maxnumber: @maxnumber,
          salt:      @salt,
          signature: @signature
        }.to_json(options)
      end
    end

    # The client-submitted solution payload.
    class Payload
      attr_accessor :algorithm, :challenge, :number, :salt, :signature

      def initialize(algorithm:, challenge:, number:, salt:, signature:)
        @algorithm = algorithm
        @challenge = challenge
        @number    = number
        @salt      = salt
        @signature = signature
      end

      def to_json(options = {})
        {
          algorithm: @algorithm,
          challenge: @challenge,
          number:    @number,
          salt:      @salt,
          signature: @signature
        }.to_json(options)
      end

      def self.from_json(string)
        data = JSON.parse(string)
        new(
          algorithm: data['algorithm'],
          challenge: data['challenge'],
          number:    data['number'],
          salt:      data['salt'],
          signature: data['signature']
        )
      end
    end

    # Payload for server-side signature verification.
    class ServerSignaturePayload
      attr_accessor :algorithm, :verification_data, :signature, :verified

      def initialize(algorithm:, verification_data:, signature:, verified:)
        @algorithm         = algorithm
        @verification_data = verification_data
        @signature         = signature
        @verified          = verified
      end

      def to_json(options = {})
        {
          algorithm:        @algorithm,
          verificationData: @verification_data,
          signature:        @signature,
          verified:         @verified
        }.to_json(options)
      end

      def self.from_json(string)
        data = JSON.parse(string)
        new(
          algorithm:         data['algorithm'],
          verification_data: data['verificationData'],
          signature:         data['signature'],
          verified:          data['verified']
        )
      end
    end

    # Typed fields returned from verify_server_signature.
    class ServerSignatureVerificationData
      attr_accessor :classification, :country, :detected_language, :email, :expire,
                    :fields, :fields_hash, :ip_address, :reasons, :score, :time, :verified

      def to_json(options = {})
        {
          classification:  @classification,
          country:         @country,
          detectedLanguage: @detected_language,
          email:           @email,
          expire:          @expire,
          fields:          @fields,
          fieldsHash:      @fields_hash,
          ipAddress:       @ip_address,
          reasons:         @reasons,
          score:           @score,
          time:            @time,
          verified:        @verified
        }.to_json(options)
      end
    end

    # Result of solve_challenge.
    class Solution
      attr_accessor :number, :took
    end

    # -------------------------------------------------------------------------
    # Module-level functions
    # -------------------------------------------------------------------------

    def self.random_bytes(length)
      OpenSSL::Random.random_bytes(length)
    end

    def self.random_int(max)
      rand(max + 1)
    end

    def self.hash_hex(algorithm, data)
      hash(algorithm, data).unpack1('H*')
    end

    def self.hash(algorithm, data)
      case algorithm
      when Algorithm::SHA1   then OpenSSL::Digest::SHA1.digest(data)
      when Algorithm::SHA256 then OpenSSL::Digest::SHA256.digest(data)
      when Algorithm::SHA512 then OpenSSL::Digest::SHA512.digest(data)
      else raise ArgumentError, "Unsupported algorithm: #{algorithm}"
      end
    end

    def self.hmac_hex(algorithm, data, key)
      hmac_hash(algorithm, data, key).unpack1('H*')
    end

    def self.hmac_hash(algorithm, data, key)
      digest_class = case algorithm
                     when Algorithm::SHA1   then OpenSSL::Digest::SHA1
                     when Algorithm::SHA256 then OpenSSL::Digest::SHA256
                     when Algorithm::SHA512 then OpenSSL::Digest::SHA512
                     else raise ArgumentError, "Unsupported algorithm: #{algorithm}"
                     end
      OpenSSL::HMAC.digest(digest_class.new, key, data)
    end

    def self.create_challenge(options)
      algorithm   = options.algorithm   || DEFAULT_ALGORITHM
      max_number  = options.max_number  || DEFAULT_MAX_NUMBER
      salt_length = options.salt_length || DEFAULT_SALT_LENGTH

      params = options.params || {}
      params['expires'] = options.expires.to_i if options.expires

      salt = options.salt || random_bytes(salt_length).unpack1('H*')
      salt += "?#{URI.encode_www_form(params)}" unless params.empty?
      salt += salt.end_with?('&') ? '' : '&'

      number    = options.number || random_int(max_number)
      challenge = hash_hex(algorithm, "#{salt}#{number}")
      signature = hmac_hex(algorithm, challenge, options.hmac_key)

      Challenge.new(
        algorithm: algorithm,
        challenge: challenge,
        maxnumber: max_number,
        salt:      salt,
        signature: signature
      )
    end

    def self.verify_solution(payload, hmac_key, check_expires = true)
      if payload.is_a?(String)
        payload = Payload.from_json(Base64.decode64(payload))
      elsif payload.is_a?(Hash)
        payload = Payload.new(
          algorithm: payload[:algorithm],
          challenge: payload[:challenge],
          number:    payload[:number],
          salt:      payload[:salt],
          signature: payload[:signature]
        )
      end

      return false unless payload.is_a?(Payload)

      %i[algorithm challenge number salt signature].each do |attr|
        value = payload.send(attr)
        return false if value.nil? || value.to_s.strip.empty?
      end

      if check_expires && payload.salt.include?('?')
        expires = URI.decode_www_form(payload.salt.split('?').last).to_h['expires'].to_i
        return false if expires && Time.now.to_i > expires
      end

      expected = create_challenge(
        ChallengeOptions.new(
          algorithm: payload.algorithm,
          hmac_key:  hmac_key,
          number:    payload.number,
          salt:      payload.salt
        )
      )
      expected.challenge == payload.challenge && expected.signature == payload.signature
    rescue ArgumentError, JSON::ParserError
      false
    end

    def self.extract_params(payload)
      URI.decode_www_form(payload.salt.split('?').last).to_h
    end

    def self.verify_fields_hash(form_data, fields, fields_hash, algorithm)
      lines       = fields.map { |field| form_data[field].to_s }
      joined_data = lines.join("\n")
      hash_hex(algorithm, joined_data) == fields_hash
    end

    def self.verify_server_signature(payload, hmac_key)
      if payload.is_a?(String)
        payload = ServerSignaturePayload.from_json(Base64.decode64(payload))
      elsif payload.is_a?(Hash)
        payload = ServerSignaturePayload.new(
          algorithm:         payload[:algorithm],
          verification_data: payload[:verification_data],
          signature:         payload[:signature],
          verified:          payload[:verified]
        )
      end

      return [false, nil] unless payload.is_a?(ServerSignaturePayload)

      %i[algorithm verification_data signature verified].each do |attr|
        value = payload.send(attr)
        return false if value.nil? || value.to_s.strip.empty?
      end

      hash_data         = hash(payload.algorithm, payload.verification_data)
      expected_signature = hmac_hex(payload.algorithm, hash_data, hmac_key)

      params = URI.decode_www_form(payload.verification_data).to_h
      verification_data = ServerSignatureVerificationData.new.tap do |v|
        v.classification    = params['classification']
        v.country           = params['country']
        v.detected_language = params['detectedLanguage']
        v.email             = params['email']
        v.expire            = params['expire']&.to_i
        v.fields            = params['fields']&.split(',')
        v.fields_hash       = params['fieldsHash']
        v.ip_address        = params['ipAddress']
        v.reasons           = params['reasons']&.split(',')
        v.score             = params['score']&.to_f
        v.time              = params['time']&.to_i
        v.verified          = params['verified'] == 'true'
      end

      now = Time.now.to_i
      is_verified = payload.verified &&
                    verification_data.verified &&
                    (verification_data.expire.nil? || verification_data.expire > now) &&
                    payload.signature == expected_signature

      [is_verified, verification_data]
    rescue ArgumentError, JSON::ParserError => e
      puts "Error decoding or parsing payload: #{e.message}"
      false
    end

    def self.solve_challenge(challenge, salt, algorithm, max, start)
      algorithm  ||= DEFAULT_ALGORITHM
      max        ||= DEFAULT_MAX_NUMBER
      start      ||= 0
      start_time   = Time.now

      (start..max).each do |n|
        if hash_hex(algorithm, "#{salt}#{n}") == challenge
          return Solution.new.tap do |s|
            s.number = n
            s.took   = Time.now - start_time
          end
        end
      end

      nil
    end
  end
end
