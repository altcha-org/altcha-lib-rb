require 'rspec'
require 'json'
require_relative '../lib/altcha'

RSpec.describe Altcha do
  # ---------------------------------------------------------------------------
  # V1 tests
  # ---------------------------------------------------------------------------

  describe Altcha::V1 do
    let(:algorithm) { Altcha::V1::Algorithm::SHA256 }
    let(:hmac_key) { 'test_key' }
    let(:salt) { 'test_salt' }
    let(:number) { 123 }
    let(:challenge_options) do
      Altcha::V1::ChallengeOptions.new(
        algorithm: algorithm,
        hmac_key:  hmac_key,
        salt:      salt,
        number:    number
      )
    end

    describe '.random_bytes' do
      it 'generates random bytes of specified length' do
        expect(Altcha::V1.random_bytes(16).size).to eq(16)
      end
    end

    describe '.random_int' do
      it 'generates a random integer between 0 and max inclusive' do
        expect(Altcha::V1.random_int(100)).to be_between(0, 100)
      end
    end

    describe '.hash' do
      it 'returns the correct hash for SHA256' do
        data = 'test data'
        expect(Altcha::V1.hash(algorithm, data)).to eq(OpenSSL::Digest::SHA256.digest(data))
      end
    end

    describe '.hmac_hash' do
      it 'returns the correct HMAC for SHA256' do
        data = 'test data'
        expect(Altcha::V1.hmac_hash(algorithm, data, hmac_key)).to eq(
          OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, hmac_key, data)
        )
      end
    end

    describe '.create_challenge' do
      it 'creates a valid challenge' do
        challenge = Altcha::V1.create_challenge(challenge_options)
        expect(challenge).to be_a(Altcha::V1::Challenge)
        expect(challenge.challenge).not_to be_empty
        expect(challenge.signature).not_to be_empty
      end
    end

    describe '.verify_solution' do
      it 'verifies a correct solution' do
        challenge = Altcha::V1.create_challenge(challenge_options)
        payload = Altcha::V1::Payload.new(
          algorithm: algorithm,
          challenge: challenge.challenge,
          number:    number,
          salt:      challenge.salt,
          signature: challenge.signature
        )
        expect(Altcha::V1.verify_solution(payload, hmac_key, false)).to be true
      end

      it 'verifies a correct solution with expires' do
        opts = Altcha::V1::ChallengeOptions.new(
          algorithm: algorithm,
          expires:   Time.now.to_i + 3600,
          hmac_key:  hmac_key,
          salt:      salt,
          number:    number
        )
        challenge = Altcha::V1.create_challenge(opts)
        payload = {
          algorithm: algorithm,
          challenge: challenge.challenge,
          number:    number,
          salt:      challenge.salt,
          signature: challenge.signature
        }
        expect(Altcha::V1.verify_solution(payload, hmac_key, true)).to be true
      end

      it 'fails to verify an incorrect solution with salt splicing' do
        opts = Altcha::V1::ChallengeOptions.new(
          algorithm: algorithm,
          expires:   Time.now.to_i + 3600,
          hmac_key:  hmac_key,
          salt:      salt,
          number:    123
        )
        challenge = Altcha::V1.create_challenge(opts)
        payload = {
          algorithm: algorithm,
          challenge: challenge.challenge,
          number:    23,
          salt:      challenge.salt + '1',
          signature: challenge.signature
        }
        expect(Altcha::V1.verify_solution(payload, hmac_key, true)).to be false
      end

      it 'fails to verify an incorrect solution' do
        payload = { algorithm: algorithm, challenge: 'wrong', number: number, salt: salt, signature: 'wrong' }
        expect(Altcha::V1.verify_solution(payload, hmac_key, false)).to be false
      end

      it 'fails to verify invalid string payload' do
        expect(Altcha::V1.verify_solution('invalid-payload', hmac_key, false)).to be false
      end
    end

    describe '.verify_fields_hash' do
      it 'verifies the hash of form fields' do
        form_data   = { 'field1' => 'value1', 'field2' => 'value2' }
        fields      = ['field1', 'field2']
        fields_hash = Altcha::V1.hash_hex(algorithm, "value1\nvalue2")
        expect(Altcha::V1.verify_fields_hash(form_data, fields, fields_hash, algorithm)).to be true
      end
    end

    describe '.verify_server_signature' do
      it 'verifies a correct server signature' do
        verification_data = 'classification=GOOD&country=US&verified=true'
        signature = Altcha::V1.hmac_hex(
          algorithm,
          Altcha::V1.hash(algorithm, verification_data),
          hmac_key
        )
        payload = Altcha::V1::ServerSignaturePayload.new(
          algorithm:         algorithm,
          verification_data: verification_data,
          signature:         signature,
          verified:          true
        )
        is_verified, _data = Altcha::V1.verify_server_signature(payload, hmac_key)
        expect(is_verified).to be true
      end

      it 'fails to verify an incorrect server signature' do
        payload = { algorithm: algorithm, verification_data: 'data', signature: 'wrong', verified: true }
        is_verified, _data = Altcha::V1.verify_server_signature(payload, hmac_key)
        expect(is_verified).to be false
      end
    end

    describe '.solve_challenge' do
      it 'solves a challenge correctly' do
        challenge = Altcha::V1.create_challenge(challenge_options)
        solution  = Altcha::V1.solve_challenge(challenge.challenge, challenge.salt, algorithm, 10_000, 0)
        expect(solution).not_to be_nil
        expect(solution.number).to eq(number)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # V2 tests
  # ---------------------------------------------------------------------------

  describe Altcha::V2 do
    let(:hmac_secret) { 'test_hmac_secret' }

    def make_server_payload(verification_data, secret, verified: true, algorithm: 'SHA-256')
      digest     = algorithm == 'SHA-256' ? 'SHA256' : algorithm.delete('-')
      hash_bytes = OpenSSL::Digest.digest(digest, verification_data)
      signature  = OpenSSL::HMAC.hexdigest(digest, secret, hash_bytes)
      Altcha::V2::ServerSignaturePayload.new(
        algorithm:         algorithm,
        verification_data: verification_data,
        signature:         signature,
        verified:          verified
      )
    end

    describe '.canonical_json' do
      it 'sorts keys alphabetically' do
        expect(Altcha::V2.canonical_json({ 'z' => 1, 'a' => 2, 'm' => 3 })).to eq('{"a":2,"m":3,"z":1}')
      end

      it 'sorts nested object keys' do
        result = Altcha::V2.canonical_json({ 'b' => { 'z' => 1, 'a' => 2 }, 'a' => 0 })
        expect(result).to eq('{"a":0,"b":{"a":2,"z":1}}')
      end

      it 'orders keys like JS JSON.stringify(sortKeys(obj))' do
        # Expected strings produced by altcha-lib (JS) canonicalJSON.
        expect(Altcha::V2.canonical_json({ 'x' => 'c', '10' => 'a', '2' => 'b' }))
          .to eq('{"2":"b","10":"a","x":"c"}')
        input = {
          'b' => 1, '01' => 1, '4294967294' => 1, '4294967295' => 1, '-1' => 1, '1.5' => 1,
          "\uFF61" => 1, "\u{1F600}" => 1, 'a' => [{ 'z' => 1, 'y' => 2, '3' => 0 }]
        }
        expect(Altcha::V2.canonical_json(input)).to eq(
          "{\"4294967294\":1,\"-1\":1,\"01\":1,\"1.5\":1,\"4294967295\":1,\"a\":[{\"3\":0,\"z\":1,\"y\":2}],\"b\":1,\"\u{1F600}\":1,\"\uFF61\":1}"
        )
      end

      it 'formats numbers like JS JSON.stringify' do
        {
          1.0                   => '1',
          -2.5                  => '-2.5',
          -0.0                  => '0',
          1e-6                  => '0.000001',
          1e-7                  => '1e-7',
          1.5e-7                => '1.5e-7',
          123_456.789           => '123456.789',
          1e20                  => '100000000000000000000',
          1e21                  => '1e+21',
          2.5e21                => '2.5e+21',
          0.1 + 0.2             => '0.30000000000000004',
          Float::NAN            => 'null',
          Float::INFINITY       => 'null',
          42                    => '42',
          (2**53) - 1           => '9007199254740991',
          12_345_678_901_234_567_890 => '12345678901234567000'
        }.each do |value, expected|
          expect(Altcha::V2.canonical_json(value)).to eq(expected), "#{value.inspect} → #{expected}"
        end
      end

      it 'verifies a challenge after a JS parse/stringify round-trip of float data' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, data: { 'x' => 1.0 },
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        # JSON.stringify(JSON.parse(...)) turns 1.0 into 1.
        js_json   = challenge.to_json.sub('"x":1.0', '"x":1')
        restored  = Altcha::V2::Challenge.from_json(js_json)
        result    = Altcha::V2.verify_solution(restored, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
      end
    end

    describe '.create_challenge' do
      it 'creates a valid v2 challenge with SHA-256' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256',
          cost: 1,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        expect(challenge).to be_a(Altcha::V2::Challenge)
        expect(challenge.parameters.algorithm).to eq('SHA-256')
        expect(challenge.parameters.nonce).to match(/\A[0-9a-f]{32}\z/)
        expect(challenge.parameters.salt).to match(/\A[0-9a-f]{32}\z/)
        expect(challenge.parameters.key_prefix).to eq('00')
        expect(challenge.signature).not_to be_nil
      end

      it 'embeds a custom expires_at' do
        future = Time.now.to_i + 3600
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1,
          hmac_signature_secret: hmac_secret, expires_at: future
        )
        expect(Altcha::V2.create_challenge(opts).parameters.expires_at).to eq(future)
      end

      it 'accepts a Time object for expires_at' do
        future = Time.now + 3600
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1,
          hmac_signature_secret: hmac_secret, expires_at: future
        )
        expect(Altcha::V2.create_challenge(opts).parameters.expires_at).to eq(future.to_i)
      end

      it 'derives key_prefix from the given counter in deterministic mode' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, counter: 42,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        expect(challenge.parameters.key_prefix).not_to be_empty
      end

      it 'adds key_signature when hmac_key_signature_secret is provided' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, counter: 0,
          hmac_signature_secret: hmac_secret,
          hmac_key_signature_secret: 'key_secret'
        )
        expect(Altcha::V2.create_challenge(opts).parameters.key_signature).not_to be_nil
      end

      it 'lowercases a custom key_prefix' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, key_prefix: 'AB',
          hmac_signature_secret: hmac_secret
        )
        expect(Altcha::V2.create_challenge(opts).parameters.key_prefix).to eq('ab')
      end
    end

    describe '.solve_challenge' do
      it 'solves a SHA-256 challenge' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        expect(solution).not_to be_nil
        expect(solution.derived_key).to start_with(challenge.parameters.key_prefix)
      end

      it 'solves and verifies a signed challenge with an uppercase key_prefix' do
        # Shared test vector: counter 42 derives f2e25aab…; challenges from other
        # implementations may carry a signed uppercase prefix.
        params = Altcha::V2::ChallengeParameters.new(
          algorithm: 'PBKDF2/SHA-256', cost: 1000, key_prefix: 'F2E',
          nonce: 'aabbccdd00112233aabbccdd00112233', salt: '11223344556677889900aabbccddeeff'
        )
        challenge = Altcha::V2::Challenge.new(
          parameters: params,
          signature:  Altcha::V2.hmac_hex(Altcha::V2.canonical_json(params.to_h), hmac_secret)
        )
        solution = Altcha::V2.solve_challenge(challenge, max_counter: 100)
        expect(solution.counter).to eq(42)
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
      end

      it 'solves a PBKDF2/SHA-256 challenge' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'PBKDF2/SHA-256', cost: 100, hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        expect(solution).not_to be_nil
        expect(solution.derived_key).to start_with(challenge.parameters.key_prefix)
      end

      it 'solves an ARGON2ID challenge' do
        begin
          require 'argon2/kdf'
        rescue LoadError
          skip 'argon2-kdf gem not available'
        end
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'ARGON2ID',
          cost: 1,
          memory_cost: 64,
          parallelism: 1,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        expect(solution).not_to be_nil
        expect(solution.derived_key).to start_with(challenge.parameters.key_prefix)
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
      end

      it 'derives ARGON2ID keys with the exact memory_cost, matching altcha-lib (JS)' do
        begin
          require 'argon2/kdf'
        rescue LoadError
          skip 'argon2-kdf gem not available'
        end
        nonce_bytes = ['aabbccdd00112233aabbccdd00112233'].pack('H*')
        salt_bytes  = ['11223344556677889900aabbccddeeff'].pack('H*')
        password    = Altcha::V2.make_password(nonce_bytes, 42)
        {
          [19_456, 1] => '235f71f8f8f81259e0c9d59501bdf17e794f686dbe9cf9c9d28c17f74795b0e2',
          [16_384, 1] => 'd315044f527ac0dcbc373ec75e0bdfd427bfd0b052e2d3e129e8630fba44ebd6',
          [1_000, 2]  => '6efe5d1efaf6e43a58a658e0e466c66bb9e72c034f4f1cb07a0d7456a1994ef6'
        }.each do |(memory_cost, parallelism), expected|
          params = Altcha::V2::ChallengeParameters.new(
            algorithm: 'ARGON2ID', nonce: '', salt: '', cost: 2,
            memory_cost: memory_cost, parallelism: parallelism
          )
          derived = Altcha::V2.derive_key(params, salt_bytes, password).unpack1('H*')
          expect(derived).to eq(expected), "memory_cost #{memory_cost}, parallelism #{parallelism}"
        end
      end

      it 'raises when an ARGON2ID challenge has no memory_cost' do
        begin
          require 'argon2/kdf'
        rescue LoadError
          skip 'argon2-kdf gem not available'
        end
        params = Altcha::V2::ChallengeParameters.new(algorithm: 'ARGON2ID', nonce: '', salt: '', cost: 1)
        expect { Altcha::V2.derive_key(params, 'salt', 'password') }.to raise_error(ArgumentError, /memory_cost/)
      end

      it 'solves a SCRYPT challenge' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SCRYPT', cost: 1024, memory_cost: 1, parallelism: 1,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        expect(solution).not_to be_nil
        expect(solution.derived_key).to start_with(challenge.parameters.key_prefix)
      end

      it 'returns nil when max_counter is exceeded' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1,
          key_prefix: 'ffffffffffffff',
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        expect(Altcha::V2.solve_challenge(challenge, max_counter: 5)).to be_nil
      end
    end

    describe '.verify_solution' do
      def make_challenge_and_solution(algorithm: 'SHA-256', cost: 1, **extra)
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: algorithm, cost: cost,
          hmac_signature_secret: 'test_hmac_secret', **extra
        )
        challenge = Altcha::V2.create_challenge(opts)
        [challenge, Altcha::V2.solve_challenge(challenge)]
      end

      it 'verifies a valid SHA-256 solution' do
        challenge, solution = make_challenge_and_solution
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
        expect(result.expired).to be false
        expect(result.invalid_signature).to be false
        expect(result.invalid_solution).to be false
      end

      it 'verifies a valid PBKDF2/SHA-256 solution' do
        challenge, solution = make_challenge_and_solution(algorithm: 'PBKDF2/SHA-256', cost: 100)
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
      end

      it 'fails with wrong hmac_signature_secret' do
        challenge, solution = make_challenge_and_solution
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: 'wrong')
        expect(result.verified).to be false
        expect(result.invalid_signature).to be true
      end

      it 'fails for an expired challenge' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1,
          expires_at: Time.now.to_i - 1,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        result    = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.expired).to be true
      end

      it 'treats expires_at equal to the current whole second as expired' do
        now = 1_800_000_000
        allow(Time).to receive(:now).and_return(Time.at(now + 0.5))
        challenge, solution = make_challenge_and_solution(expires_at: now)
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.expired).to be true
      end

      it 'treats expires_at 0 as no expiry' do
        challenge, solution = make_challenge_and_solution(expires_at: 0)
        result = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
        expect(result.expired).to be false
      end

      it 'returns invalid_signature for a tampered non-numeric expiresAt instead of raising' do
        challenge, solution = make_challenge_and_solution(expires_at: Time.now.to_i + 600)
        ['abc', [1], { 'a' => 1 }].each do |tampered_expires_at|
          data = JSON.parse(challenge.to_json)
          data['parameters']['expiresAt'] = tampered_expires_at
          tampered = Altcha::V2::Challenge.from_h(data)
          result   = Altcha::V2.verify_solution(tampered, solution, hmac_signature_secret: hmac_secret)
          expect(result.verified).to be false
          expect(result.expired).to be false
          expect(result.invalid_signature).to be true
        end
      end

      it 'fails when challenge has no signature' do
        opts = Altcha::V2::CreateChallengeOptions.new(algorithm: 'SHA-256', cost: 1)
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        result    = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.invalid_signature).to be true
      end

      it 'fails when the solution derived_key is tampered' do
        challenge, solution = make_challenge_and_solution
        tampered = Altcha::V2::Solution.new(counter: solution.counter, derived_key: 'aa' * 32)
        result   = Altcha::V2.verify_solution(challenge, tampered, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.invalid_solution).to be true
      end

      it 'returns invalid_solution for malformed solution fields instead of raising' do
        challenge, solution = make_challenge_and_solution
        [
          [solution.counter.to_s, solution.derived_key],
          [nil, solution.derived_key],
          [solution.counter, nil],
          [solution.counter, 123]
        ].each do |counter, derived_key|
          malformed = Altcha::V2::Solution.new(counter: counter, derived_key: derived_key)
          result    = Altcha::V2.verify_solution(challenge, malformed, hmac_signature_secret: hmac_secret)
          expect(result.verified).to be false
          expect(result.invalid_signature).to be false
          expect(result.invalid_solution).to be true
        end
      end

      it 'returns invalid_solution for a non-string derived_key on the key signature path' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, counter: 0,
          hmac_signature_secret: hmac_secret,
          hmac_key_signature_secret: 'key_secret'
        )
        challenge = Altcha::V2.create_challenge(opts)
        malformed = Altcha::V2::Solution.new(counter: 0, derived_key: nil)
        result    = Altcha::V2.verify_solution(
          challenge, malformed,
          hmac_signature_secret: hmac_secret,
          hmac_key_signature_secret: 'key_secret'
        )
        expect(result.verified).to be false
        expect(result.invalid_solution).to be true
      end

      it 'returns invalid_solution for a non-hex or odd-length derived_key on the key signature path' do
        key_hex   = 'a0' * 32
        params    = Altcha::V2::ChallengeParameters.new(
          algorithm: 'SHA-256', nonce: '00' * 16, salt: '00' * 16, cost: 1,
          key_signature: Altcha::V2.hmac_hex([key_hex].pack('H*'), 'key_secret')
        )
        challenge = Altcha::V2::Challenge.new(
          parameters: params,
          signature:  Altcha::V2.hmac_hex(Altcha::V2.canonical_json(params.to_h), hmac_secret)
        )
        verify = lambda do |derived_key|
          Altcha::V2.verify_solution(
            challenge, Altcha::V2::Solution.new(counter: 0, derived_key: derived_key),
            hmac_signature_secret: hmac_secret, hmac_key_signature_secret: 'key_secret'
          )
        end

        expect(verify.call(key_hex).verified).to be true
        expect(verify.call(key_hex.upcase).verified).to be true
        # Each of these decodes to the real key bytes with pack('H*').
        [key_hex[0..-2], key_hex.tr('a', ':'), key_hex.tr('0', 'g'), "#{key_hex}\n"].each do |malformed|
          result = verify.call(malformed)
          expect(result.verified).to be(false), malformed.inspect
          expect(result.invalid_solution).to be true
        end
      end

      it 'fails when the derived key does not satisfy key_prefix (slow path)' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1,
          key_prefix: 'ffffffffffffff',
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)

        # Honestly derive the key for counter 0 without brute-forcing a
        # counter that actually satisfies key_prefix.
        nonce_bytes    = [challenge.parameters.nonce].pack('H*')
        salt_bytes     = [challenge.parameters.salt].pack('H*')
        password_bytes = Altcha::V2.make_password(nonce_bytes, 0)
        derived_key    = Altcha::V2.derive_key(challenge.parameters, salt_bytes, password_bytes).unpack1('H*')
        expect(derived_key).not_to start_with(challenge.parameters.key_prefix)

        solution = Altcha::V2::Solution.new(counter: 0, derived_key: derived_key)
        result   = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.invalid_solution).to be true
      end

      it 'verifies via key signature fast path' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SHA-256', cost: 1, counter: 0,
          hmac_signature_secret: hmac_secret,
          hmac_key_signature_secret: 'key_secret'
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        result    = Altcha::V2.verify_solution(
          challenge, solution,
          hmac_signature_secret: hmac_secret,
          hmac_key_signature_secret: 'key_secret'
        )
        expect(result.verified).to be true
      end

      it 'verifies a valid SCRYPT solution' do
        opts = Altcha::V2::CreateChallengeOptions.new(
          algorithm: 'SCRYPT', cost: 1024, memory_cost: 1, parallelism: 1,
          hmac_signature_secret: hmac_secret
        )
        challenge = Altcha::V2.create_challenge(opts)
        solution  = Altcha::V2.solve_challenge(challenge)
        result    = Altcha::V2.verify_solution(challenge, solution, hmac_signature_secret: hmac_secret)
        expect(result.verified).to be true
      end

      it 'round-trips through JSON serialization' do
        challenge, solution = make_challenge_and_solution
        payload  = Altcha::V2::Payload.new(challenge: challenge, solution: solution)
        restored = Altcha::V2::Payload.from_json(payload.to_json)
        result   = Altcha::V2.verify_solution(
          restored.challenge, restored.solution,
          hmac_signature_secret: hmac_secret
        )
        expect(result.verified).to be true
      end
    end

    describe '.parse_verification_data' do
      it 'parses booleans, integers, floats, and strings' do
        data   = 'verified=true&score=0.8&time=1234567890&classification=GOOD'
        result = Altcha::V2.parse_verification_data(data)
        expect(result['verified']).to be true
        expect(result['score']).to eq(0.8)
        expect(result['time']).to eq(1234567890)
        expect(result['classification']).to eq('GOOD')
      end

      it 'converts fields and reasons to arrays' do
        data   = 'fields=name,email&reasons=too_fast'
        result = Altcha::V2.parse_verification_data(data)
        expect(result['fields']).to eq(%w[name email])
        expect(result['reasons']).to eq(['too_fast'])
      end
    end

    describe '.verify_fields_hash' do
      it 'returns true for a matching hash' do
        form_data   = { 'name' => 'Alice', 'email' => 'alice@example.com' }
        fields      = %w[name email]
        fields_hash = OpenSSL::Digest::SHA256.hexdigest("Alice\nalice@example.com")
        expect(Altcha::V2.verify_fields_hash(form_data: form_data, fields: fields, fields_hash: fields_hash)).to be true
      end

      it 'returns false for a non-matching hash' do
        expect(Altcha::V2.verify_fields_hash(form_data: { 'name' => 'Alice' }, fields: %w[name], fields_hash: 'bad')).to be false
      end
    end

    describe '.verify_server_signature' do
      it 'verifies a valid server signature' do
        payload = make_server_payload('classification=GOOD&verified=true', hmac_secret)
        result  = Altcha::V2.verify_server_signature(payload: payload, hmac_secret: hmac_secret)
        expect(result.verified).to be true
        expect(result.expired).to be false
        expect(result.invalid_signature).to be false
        expect(result.invalid_solution).to be false
        expect(result.verification_data['classification']).to eq('GOOD')
        expect(result.verification_data['verified']).to be true
      end

      it 'fails with wrong hmac_secret' do
        payload = make_server_payload('verified=true', hmac_secret)
        result  = Altcha::V2.verify_server_signature(payload: payload, hmac_secret: 'wrong')
        expect(result.verified).to be false
        expect(result.invalid_signature).to be true
      end

      it 'fails when payload.verified is false' do
        payload = make_server_payload('verified=false', hmac_secret, verified: false)
        result  = Altcha::V2.verify_server_signature(payload: payload, hmac_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.invalid_solution).to be true
      end

      it 'fails for an expired verification' do
        vd      = "verified=true&expire=#{Time.now.to_i - 1}"
        payload = make_server_payload(vd, hmac_secret)
        result  = Altcha::V2.verify_server_signature(payload: payload, hmac_secret: hmac_secret)
        expect(result.verified).to be false
        expect(result.expired).to be true
      end

      it 'round-trips through JSON serialization' do
        payload  = make_server_payload('classification=GOOD&verified=true', hmac_secret)
        restored = Altcha::V2::ServerSignaturePayload.from_json(payload.to_json)
        result   = Altcha::V2.verify_server_signature(payload: restored, hmac_secret: hmac_secret)
        expect(result.verified).to be true
      end

      it 'round-trips through base64 serialization' do
        payload  = make_server_payload('classification=GOOD&verified=true', hmac_secret)
        b64      = Base64.strict_encode64(payload.to_json)
        restored = Altcha::V2::ServerSignaturePayload.from_base64(b64)
        result   = Altcha::V2.verify_server_signature(payload: restored, hmac_secret: hmac_secret)
        expect(result.verified).to be true
      end
    end
  end
end
