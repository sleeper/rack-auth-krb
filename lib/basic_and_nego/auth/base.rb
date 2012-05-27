module BasicAndNego
  module Auth
    class Base
      include Responses

      attr_reader :response, :client_name, :headers

      def initialize(request, logger, realm, keytab)
        @request = request
        @logger = logger
        @realm = realm
        @keytab = keytab
      end

    end
  end
end
