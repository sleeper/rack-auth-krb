require 'rack/auth/krb/request'
require 'krb/authenticator'
require 'socket'

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
            @hostname = Socket::gethostname
            @service = service || "http@#{hostname}"
          end

          def call(env)
            session = env['rack.session']
            headers = {}
            if session.nil? || !session['REMOTE_USER']
              env.logger "User not authenticated : delegate to Krb authenticator"
              req = ::Rack::Auth::Krb::Request.new(env)

              a = ::Krb::Authenticator.new( req, service, realm, keytab, env.logger )

              if !a.authenticate
                return a.response
              end

              env['REMOTE_USER'] = a.client_name
              if session
                session['REMOTE_USER'] = a.client_name
              end

              headers = a.headers
            else
              env.logger "User #{session['REMOTE_USER']} already authenticated"
              env['REMOTE_USER'] = session['REMOTE_USER']
            end

            super(env, headers)
          end

          def post_process(env, status, headers, body, additional_headers)
            [status, headers.merge(additional_headers), body]
          end

        end
      end
    end
  end
end
