require 'rack/request'
module Goliath
  module Rack
    module Auth
      module Krb
        class BasicAndNego
          def initialize(app, realm, keytab)
            @app = app
            @realm = realm
            @keytab = keytab
            @additional_headers = {}
          end

          def call(env)
            service = 'http@ncepspa240'
            req = Rack::Auth::Krb::Request.new(env)

            a = KrbAuthenticator.new( req, service, realm, keytab )

            if !a.authenticate
              return a.response
            end

            super(env, a)
          end

          def post_process(env, status, headers, body, auth)
            [status, headers.merge(auth.headers), body]
          end

        end
      end
    end
  end
end
