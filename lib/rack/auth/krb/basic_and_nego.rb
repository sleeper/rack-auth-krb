require 'basic_and_nego/request'
require 'basic_and_nego/processor'

module Rack
  module Auth
    module Krb
      class BasicAndNego

        def initialize(app, realm, keytab, service=nil, paths_only=Array.new)
          @app = app
          @realm = realm
          @keytab = keytab
          @service = service
          #paths_only allows to request an authentication process only for specified paths
          @paths_only = paths_only 
        end

        def call(env)

          a = nil
          
          if @paths_only.empty? or @paths_only.include?(env["PATH_INFO"])
			# Either user rack.logger if defined or create on
			# logger defaulting to rack.errors		  
            logger = env['rack.logger'] || ::Logger.new(env['rack.errors'])
            a = ::BasicAndNego::Processor.new(env, logger, @realm, @keytab, @service)
            a.process_request
            return a.response if a.response
          end
          
          status, headers, body = @app.call(env)
          
          if a
            headers.merge!(a.headers)
          end
          
          [status, headers, body]
        end
      end
    end
  end
end
