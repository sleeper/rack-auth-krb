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
            req = Request.new(env)

            a = KrbAuthenticator.new( req, service, realm, keytab )

            if !a.authenticate
              return a.response
            end

            status, headers, body = @app.call(env)
            [status, headers.merge(a.headers), body]
        end
      end
    end
  end
end
