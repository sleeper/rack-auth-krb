require 'rack/auth/abstract/handler'
require 'rack/auth/krb/request'
require 'gssapi'
#require 'rack/auth/digest/request'
#require 'rack/auth/digest/params'
#require 'rack/auth/digest/nonce'

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
          host = 'ncepspa240'
          service = 'host/ncepspa240@NCE.AMADEUS.NET'
          keytab = '/etc/krb5.keytab'

          auth = Request.new(env)

          puts "FRED: #{env.inspect}"
          puts "FRED: #{auth.provided?}"

          unless auth.provided?
            return unauthorized
          end

          valid_auth = false
          srv = GSSAPI::Simple.new(host, service, keytab)
          srv.acquire_credentials

          if auth.negociate?
            token = auth.params
            puts "FRED: Negociate auth token=#{token}"
            # TODO: Play with Kerberos to authenticate user using token
            otok = srv.accept_context(Base64.strict_decode64(token.chomp))
            valid_auth = true
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

