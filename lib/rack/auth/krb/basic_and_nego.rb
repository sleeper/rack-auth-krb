require 'basic_and_nego/request'
require 'basic_and_nego/processor'

module Rack
  module Auth
    module Krb
      class BasicAndNego

        def initialize(app, realm, keytab, service=nil)
          @app = app
          @realm = realm
          @keytab = keytab
          @service = service
        end

        def call(env)
          a = ::BasicAndNego::Processor.new(env, env['rack.logger'], @realm, @keytab, @service)
          a.process_request

          return a.response if a.response

          status, headers, body = @app.call(env)

          [status, headers.merge(a.headers), body]
        end
      end
    end
  end
end
