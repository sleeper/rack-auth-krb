require 'basic_and_nego/request'
require 'basic_and_nego/logic'
require 'basic_and_nego/nulllogger'
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
          a = ::BasicAndNego::Logic.new(env, env['rack.logger'], realm, keytab)
          a.process_request

          return a.response unless a.response.nil?

          status, headers, body = @app.call(env)

          [status, headers.merge(a.headers), body]
        end
      end
    end
  end
end
