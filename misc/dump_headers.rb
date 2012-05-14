#!/usr/bin/env ruby

require 'bundler/setup'
require 'goliath'
require 'rack/auth/krb'

class DumpHeaders < Goliath::API
  # default to JSON output, allow Yaml as secondary
  use Goliath::Rack::Render, ['json', 'yaml']
  use Rack::Auth::Krb::BasicSPNEGO

  def on_headers(env, headers)
    env.logger.info 'received headers: ' + headers.inspect
  end

  def response(env)
    [200, {}, "Hello #{env['REMOTE_USER']}"]
  end
end
