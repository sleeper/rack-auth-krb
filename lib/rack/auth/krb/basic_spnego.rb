require 'rack/auth/abstract/handler'
require 'rack/auth/krb/request'
require 'gssapi'
require 'base64'

module Rack
  module Auth
    module Krb
      class BasicSPNEGO < AbstractHandler
        attr_reader :gssapi

        def initialize(app, realm, keytab)
          @app = app
          @realm = realm
          @keytab = keytab
        end

        def call(env)
          # DEV mode
          @env = env
          service = 'http@ncepspa240' # FRED
#          host = 'NCE.AMADEUS.NET'
#          keytab = '/etc/krb5.keytab'

          auth = Request.new(@env)

          unless auth.provided?
            return unauthorized
          end

#          valid_auth = false

          setup_gssapi( service )

          if !gssapi.acquire_credentials
            return error
          end

          if auth.negotiate?
            if !negotiate(auth)
              return unauthorized
            end

          elsif auth.basic?
            user, password = auth.credentials
            puts "FRED: Basic auth user=#{user} pass=#{password}"
            # TODO: Play with Kerberos to authenticate user
            valid_auth = true
          else
            return bad_request
          end

#          if valid_auth
            #           env['REMOTE_USER'] = auth.username

            return @app.call(env)
#          end

#          unauthorized
        end

        private

        def challenge(hash={})
          "Negotiate"
        end

        def valid?(auth)
          valid_opaque?(auth) && valid_nonce?(auth) && valid_digest?(auth)
        end

        def setup_gssapi(service)
          @gssapi = GSSAPI::Simple.new(@realm, service, @keytab)
        end

        def acquire_credentials
          return false if gssapi.nil?

          acquired = false
          begin
            gssapi.acquire_credentials
            acquired = true
          rescue GSSAPI::GssApiError => e
            puts "FRED[ERROR]: #{e.message}"
          end
          acquired
        end

        def accept_token( tok )
            otok = nil
            begin
              otok = gssapi.accept_context(tok)
            rescue GSSAPI::GssApiError => e
              puts "FRED[ERROR]: #{e.message}"
            end
            otok
        end

        def negotiate(req)
            token = req.params
            puts "FRED: Negotiate auth token=#{token}"

            otok = accept_token(Base64.strict_decode64(token.chomp))

            if otok.nil?
              return false
            end

            tok_b64 = Base64.strict_encode64(otok)
            @env['WWW-Authenticate'] = "Negotiate #{tok_b64}"
            return true
        end
      end
    end
  end
end

