#!/usr/bin/env ruby

require 'bundler/setup'
require 'rack/session/cookie'
require 'goliath'
require 'goliath/rack/auth/krb/basic_and_nego'

class DumpHeaders < Goliath::API
  # default to JSON output, allow Yaml as secondary
  use Goliath::Rack::Render, ['json', 'yaml']
  # Must be placed *before* BasicAndNego if we want it to use sessions !
  use Rack::Session::Cookie
  use Goliath::Rack::Auth::Krb::BasicAndNego, 'NCE.AMADEUS.NET', '/etc/krb5.keytab'

  def on_headers(env, headers)
    env.logger.info 'received headers: ' + headers.inspect
  end

  def response(env)
    [200, {}, "Hello #{env['REMOTE_USER']}"]
  end
end
