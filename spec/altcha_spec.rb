require 'rspec'
require 'json'
require_relative '../lib/altcha'

RSpec.describe Altcha do
  let(:algorithm) { Altcha::Algorithm::SHA256 }
  let(:hmac_key) { 'test_key' }
  let(:salt) { 'test_salt' }
  let(:number) { 123 }
  let(:challenge_options) { Altcha::ChallengeOptions.new.tap do |co|
    co.algorithm = algorithm
    co.hmac_key = hmac_key
    co.salt = salt
    co.number = number
  end }

  describe '.random_bytes' do
    it 'generates random bytes of specified length' do
      bytes = Altcha.random_bytes(16)
      expect(bytes.size).to eq(16)
    end
  end

  describe '.random_int' do
    it 'generates a random integer between 0 and max inclusive' do
      int = Altcha.random_int(100)
      expect(int).to be_between(0, 100)
    end
  end

  describe '.hash' do
    it 'returns the correct hash for SHA256' do
      data = 'test data'
      expected_hash = OpenSSL::Digest::SHA256.digest(data)
      hash = Altcha.hash(algorithm, data)
      expect(hash).to eq(expected_hash)
    end
  end

  describe '.hmac_hash' do
    it 'returns the correct HMAC for SHA256' do
      data = 'test data'
      expected_hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, hmac_key, data)
      hmac = Altcha.hmac_hash(algorithm, data, hmac_key)
      expect(hmac).to eq(expected_hmac)
    end
  end

  describe '.create_challenge' do
    it 'creates a valid challenge' do
      challenge = Altcha.create_challenge(challenge_options)
      expect(challenge).to be_a(Altcha::Challenge)
      expect(challenge.challenge).not_to be_empty
      expect(challenge.signature).not_to be_empty
    end
  end

  describe '.verify_solution' do
    it 'verifies a correct solution' do
      challenge = Altcha.create_challenge(challenge_options)
      payload = Altcha::Payload.new.tap do |p|
        p.algorithm = algorithm
        p.challenge = challenge.challenge
        p.number = number
        p.salt = salt
        p.signature = challenge.signature
      end
      expect(Altcha.verify_solution(payload, hmac_key, false)).to be true
    end

    it 'verifies a correct solution with expires' do
      challenge_options_with_expires = Altcha::ChallengeOptions.new.tap do |co|
        co.algorithm = algorithm
        co.expires = Time.now.to_i + 3600
        co.hmac_key = hmac_key
        co.salt = salt
        co.number = number
      end 
      challenge = Altcha.create_challenge(challenge_options_with_expires)
      payload = Altcha::Payload.new.tap do |p|
        p.algorithm = algorithm
        p.challenge = challenge.challenge
        p.number = number
        p.salt = challenge.salt
        p.signature = challenge.signature
      end
      expect(Altcha.verify_solution(payload, hmac_key, true)).to be true
    end

    it 'fails to verify an incorrect solution' do
      payload = { algorithm: algorithm, challenge: 'wrong_challenge', number: number, salt: salt, signature: 'wrong_signature' }
      expect(Altcha.verify_solution(payload, hmac_key, false)).to be false
    end

    it 'fails to verify invalid string payload' do
      payload = 'invalid-payload'
      expect(Altcha.verify_solution(payload, hmac_key, false)).to be false
    end
  end

  describe '.verify_fields_hash' do
    it 'verifies the hash of form fields' do
      form_data = { 'field1' => ['value1'], 'field2' => ['value2'] }
      fields = ['field1', 'field2']
      fields_hash = Altcha.hash_hex(algorithm, "value1\nvalue2")
      expect(Altcha.verify_fields_hash(form_data, fields, fields_hash, algorithm)).to be true
    end
  end

  describe '.verify_server_signature' do
    it 'verifies a correct server signature' do
      verification_data = 'classification=GOOD&country=US&verified=true'
      signature = Altcha.hmac_hex(algorithm, Altcha.hash(algorithm, verification_data), hmac_key)
      payload = Altcha::ServerSignaturePayload.new.tap do |p|
        p.algorithm = algorithm
        p.verification_data = verification_data
        p.signature = signature
        p.verified = true
      end
      is_verified, _verification_data = Altcha.verify_server_signature(payload, hmac_key)
      expect(is_verified).to be true
    end

    it 'fails to verify an incorrect server signature' do
      payload = { algorithm: algorithm, verification_data: 'data', signature: 'wrong_signature', verified: true }
      is_verified, _verification_data = Altcha.verify_server_signature(payload, hmac_key)
      expect(is_verified).to be false
    end
  end

  describe '.solve_challenge' do
    it 'solves a challenge correctly' do
      challenge = Altcha.create_challenge(challenge_options)
      solution = Altcha.solve_challenge(challenge.challenge, salt, algorithm, 10_000, 0)
      expect(solution).not_to be_nil
      expect(solution.number).to eq(number)
    end
  end
end
