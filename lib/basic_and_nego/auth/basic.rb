require 'basic_and_nego/auth/base'
require 'basic_and_nego/auth/krb'

module BasicAndNego
  module Auth
    class Basic < Base

      def initialize(request, logger, realm, keytab, service)
        super
        @krb = BasicAndNego::Auth::Krb.new(@logger, @realm, @keytab)
      end

      def process
        @logger.debug "Basic scheme proposed by client"
        user, password = @request.credentials
        authenticate(user, password)
        @client_name = user unless @response
      end

      private

      def authenticate(user, password)
        unless @krb.authenticate(user, password)
          @logger.debug "Unable to authenticate (401)"
          @response = unauthorized
        end
      end

    end
  end
end
