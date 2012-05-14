require 'rack/auth/abstract/handler'
require 'rack/auth/krb/request'
require 'gssapi'
require 'base64'

module Rack
  module Auth
    module Krb
      class BasicSPNEGO < AbstractHandler

        def initialize(app, user_field = 'username', password_field = 'password', realm = nil)
          @kerberos = nil
          @app = app
          @user_field = user_field
          @password_field = password_field
          @realm = realm
        end

        def call(env)
          # DEV mode
          service = 'http@ncepspa240' # FRED
          host = 'NCE.AMADEUS.NET'
          keytab = '/etc/krb5.keytab'

          auth = Request.new(env)

          unless auth.provided?
            return unauthorized
          end

          valid_auth = false
          srv = GSSAPI::Simple.new(host, service, keytab)
          srv.acquire_credentials

          if auth.negotiate?
            token = auth.params
            puts "FRED: Negotiate auth token=#{token}"
            otok = nil
            begin
              otok = srv.accept_context(Base64.strict_decode64(token.chomp))
              valid_auth = true
            rescue GSSAPI::GssApiError => e
              puts "FRED[ERROR]: #{e.message}"
              valid_auth = false
            end

          elsif auth.basic?
            user, password = auth.credentials
            puts "FRED: Basic auth user=#{user} pass=#{password}"
            # TODO: Play with Kerberos to authenticate user
            valid_auth = true
          else
            return bad_request
          end

          if valid_auth
            env['REMOTE_USER'] = auth.username

            return @app.call(env)
          end

          unauthorized
        end

        private

        def challenge(hash={})
          "Negotiate"
        end

        def valid?(auth)
          valid_opaque?(auth) && valid_nonce?(auth) && valid_digest?(auth)
        end
      end
    end
  end
end

