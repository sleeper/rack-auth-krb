require 'goliath'
require 'basic_and_nego/request'
require 'basic_and_nego/processor'
require 'ruby-debug'

module Goliath
  module Rack
    module Auth
      module Krb
        class BasicAndNego
          include Goliath::Rack::AsyncMiddleware
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
              a = ::BasicAndNego::Processor.new(env, env.logger, @realm, @keytab, @service)
              a.process_request
              return a.response if a.response
            end
            
            new_headers = (a.nil?) ? {} : a.headers

            super(env, new_headers)
          end

          def post_process(env, status, headers, body, additional_headers)
            [status, headers.merge(additional_headers), body]
          end

        end
      end
    end
  end
end
