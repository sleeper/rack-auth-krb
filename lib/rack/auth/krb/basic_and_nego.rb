require 'rack/auth/krb/request'
require 'krb/authenticator'
require 'socket'
require 'rack/auth/krb/nulllogger'

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
          session = env['rack.session']
          headers = {}
          if session.nil? || !session['REMOTE_USER']
            req = ::Rack::Auth::Krb::Request.new(env)

            logger = req.request.logger || NullLogger.new

            a = ::Krb::Authenticator.new( req, service, realm, keytab, logger)

            if !a.authenticate
              return a.response
            end

            env['REMOTE_USER'] = a.client_name
            headers = a.headers

          else
            env['REMOTE_USER'] = session['REMOTE_USER']
          end

          status, headers, body = @app.call(env)

          [status, headers.merge(headers), body]
        end
      end
    end
  end
end
