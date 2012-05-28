require 'basic_and_nego/auth/responses'

module BasicAndNego
  module Auth
    class Base
      include Responses

      attr_reader :response, :client_name, :headers

      def initialize(request, logger, realm, keytab, service)
        @request = request
        @logger = logger
        @realm = realm
        @keytab = keytab
        @service = service
      end

    end
  end
end
