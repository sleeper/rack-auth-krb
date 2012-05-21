require 'rack/auth/krb/request'
require 'krb/authenticator'

module Goliath
  module Rack
    module Auth
      module Krb
        class BasicAndNego
          include Goliath::Rack::AsyncMiddleware

          attr_reader :realm, :keytab, :hostname, :service

          def initialize(app, realm, keytab, service=nil)
            @app = app
            @realm = realm
            @keytab = keytab
          end

          def call(env)
            a = BasicAndNego::Logic.new(env, realm, keytab)

            return a.response unless a.response.nil?

            super(env, a.headers)
          end

          def post_process(env, status, headers, body, additional_headers)
            [status, headers.merge(additional_headers), body]
          end

        end
      end
    end
  end
end
