#!/usr/bin/env ruby

require 'bundler/setup'
require 'goliath'
require 'goliath/krb_basic_and_nego'

class DumpHeaders < Goliath::API
  # default to JSON output, allow Yaml as secondary
  use Goliath::Rack::Render, ['json', 'yaml']
#  use Rack::Auth::Krb::BasicSPNEGO, 'NCE.AMADEUS.NET', '/etc/krb5.keytab'
  use Goliath::Rack::Auth::Krb::BasicAndNego, 'NCE.AMADEUS.NET', '/etc/krb5.keytab'

  def on_headers(env, headers)
    env.logger.info 'received headers: ' + headers.inspect
  end

  def response(env)
    [200, {}, "Hello #{env['REMOTE_USER']}"]
  end
end
