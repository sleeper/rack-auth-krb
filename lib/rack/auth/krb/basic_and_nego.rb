require 'rack/auth/krb/request'
require 'krb/authenticator'
require 'socket'

module Rack
  module Auth
    module Krb
      class BasicAndNego
        attr_reader :realm, :keytab, :hostname, :service

        def initialize(app, realm, keytab, service=nil)
          @app = app
          @realm = realm
          @keytab = keytab
          @hostname = Socket::gethostname
          @service = service || "http@#{hostname}"
        end

        def call(env)
            req = ::Rack::Auth::Krb::Request.new(env)

            a = ::Krb::Authenticator.new( req, service, realm, keytab, env.logger )

            if !a.authenticate
              return a.response
            end

            env['REMOTE_USER'] = a.client_name

            status, headers, body = @app.call(env)

            [status, headers.merge(a.headers), body]
        end
      end
    end
  end
end
