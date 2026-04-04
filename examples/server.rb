# frozen_string_literal: true

# Basic HTTP server demonstrating ALTCHA v2 challenge/verify flow.
#
# Usage:
#   HMAC_SECRET=your-secret ruby examples/server.rb
#
# Endpoints:
#   GET  /challenge  — issues a new challenge (JSON)
#   POST /submit     — verifies an altcha payload from a form or JSON body
#
# Requires:
#   gem install webrick

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'webrick'
require 'json'
require 'base64'
require 'securerandom'
require 'uri'
require 'altcha'

HMAC_SECRET     = ENV.fetch('HMAC_SECRET', 'change-me-in-production')
HMAC_KEY_SECRET = ENV.fetch('HMAC_KEY_SECRET', 'change-me-in-production')
PORT            = ENV.fetch('PORT', 3000).to_i

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cors_headers(response)
  response['Access-Control-Allow-Origin']  = '*'
  response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response['Access-Control-Allow-Headers'] = 'Content-Type'
end

def json_response(response, status, body)
  response.status          = status
  response['Content-Type'] = 'application/json'
  response.body            = body.to_json
end

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

server = WEBrick::HTTPServer.new(
  Port:        PORT,
  Logger:      WEBrick::Log.new($stdout, WEBrick::Log::INFO),
  AccessLog:   [[
    $stdout,
    '%{%Y-%m-%dT%H:%M:%S}t %m %U %s'
  ]]
)

# ---------------------------------------------------------------------------
# GET /challenge
# ---------------------------------------------------------------------------

server.mount_proc '/challenge' do |req, res|
  cors_headers(res)

  if req.request_method == 'OPTIONS'
    res.status = 204
    next
  end

  unless req.request_method == 'GET'
    json_response(res, 405, { error: 'Method not allowed' })
    next
  end

  options = Altcha::V2::CreateChallengeOptions.new(
    algorithm:                 'PBKDF2/SHA-256',
    cost:                      5_000,
    counter:                   SecureRandom.random_number(5_000..10_000),
    expires_at:                Time.now + 300,   # 5 minutes
    hmac_signature_secret:     HMAC_SECRET,
    hmac_key_signature_secret: HMAC_KEY_SECRET
  )

  challenge = Altcha::V2.create_challenge(options)
  json_response(res, 200, challenge.to_h)
end

# ---------------------------------------------------------------------------
# POST /submit
# ---------------------------------------------------------------------------

server.mount_proc '/submit' do |req, res|
  cors_headers(res)

  if req.request_method == 'OPTIONS'
    res.status = 204
    next
  end

  unless req.request_method == 'POST'
    json_response(res, 405, { error: 'Method not allowed' })
    next
  end

  # Parse the request body based on Content-Type.
  content_type = req['Content-Type'].to_s
  form_data    = {}
  altcha_value = nil

  begin
    if content_type.include?('application/json')
      parsed       = JSON.parse(req.body || '{}')
      altcha_value = parsed.delete('altcha')
      form_data    = parsed

    elsif content_type.include?('application/x-www-form-urlencoded')
      parsed       = URI.decode_www_form(req.body || '').to_h
      altcha_value = parsed.delete('altcha')
      form_data    = parsed

    else
      json_response(res, 415, { error: 'Unsupported content type' })
      next
    end
  rescue JSON::ParserError
    json_response(res, 400, { error: 'Invalid JSON body' })
    next
  end

  if altcha_value.nil? || altcha_value.empty?
    json_response(res, 400, { error: 'Missing altcha field' })
    next
  end

  # Decode and verify the ALTCHA payload.
  # Detect type by presence of 'verificationData' (server signature) vs 'solution' (client payload).
  begin
    decoded = JSON.parse(Base64.decode64(altcha_value))

    result = if decoded.key?('verificationData')
               Altcha::V2.verify_server_signature(
                 payload:     Altcha::V2::ServerSignaturePayload.from_h(decoded),
                 hmac_secret: HMAC_SECRET
               )
             else
               payload = Altcha::V2::Payload.new(
                 challenge: Altcha::V2::Challenge.from_h(decoded['challenge']),
                 solution:  Altcha::V2::Solution.new(
                   counter:     decoded['solution']['counter'],
                   derived_key: decoded['solution']['derivedKey']
                 )
               )
               Altcha::V2.verify_solution(
                 payload.challenge,
                 payload.solution,
                 hmac_signature_secret:     HMAC_SECRET,
                 hmac_key_signature_secret: HMAC_KEY_SECRET
               )
             end
  rescue StandardError => e
    json_response(res, 400, { error: "Invalid altcha payload: #{e.message}" })
    next
  end

  altcha_result = {
    verified:          result.verified,
    expired:           result.expired,
    invalid_signature: result.invalid_signature,
    invalid_solution:  result.invalid_solution,
    time:              result.time
  }
  altcha_result[:verification_data] = result.verification_data if result.respond_to?(:verification_data)

  unless result.verified
    reason = if result.expired
               'Challenge expired'
             elsif result.invalid_signature
               'Invalid challenge signature'
             else
               'Incorrect solution'
             end
    json_response(res, 400, { error: reason, altcha: altcha_result })
    next
  end

  # The form data is now trusted. Process it here.
  $stdout.puts "Verified submission: #{form_data}"

  json_response(res, 200, { success: true, received: form_data, altcha: altcha_result })
end

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

trap('INT')  { server.shutdown }
trap('TERM') { server.shutdown }

$stdout.puts "Listening on http://localhost:#{PORT}"
$stdout.puts "HMAC_SECRET: #{HMAC_SECRET == 'change-me-in-production' ? '(default — set HMAC_SECRET env var)' : '(set)'}"
$stdout.puts "HMAC_KEY_SECRET: #{HMAC_KEY_SECRET == 'change-me-in-production' ? '(default — set HMAC_KEY_SECRET env var)' : '(set)'}"
server.start
