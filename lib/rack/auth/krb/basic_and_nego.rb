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
          # Either user rack.logger if defined or create on
          # logger defaulting to rack.errors
          #
          logger = env['rack.logger'] || ::Logger.new(env['rack.errors'])
          a = ::BasicAndNego::Processor.new(env, logger, @realm, @keytab, @service)
          a.process_request

          return a.response if a.response

          status, headers, body = @app.call(env)

          [status, headers.merge(a.headers), body]
        end
      end
    end
  end
end
