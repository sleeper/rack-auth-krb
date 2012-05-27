require 'gssapi'

module BasicAndNego
  module Auth
    class GSS
      attr_reader :gssapi, :logger

      #
      # Can raise GSSAPI::GssApiError
      #
      def initialize(logger, service, realm, keytab)
        @logger = logger
        @service = service
        @realm = realm
        @keytab = keytab
        @gssapi = GSSAPI::Simple.new(@realm, service, @keytab)

        gssapi.acquire_credentials
      end

      #
      #  Attempt to authenticate the furnished token against gssapi
      #
      # It return nil (in case of error) or the token sent back
      # by the gssapi if the authentication is successfull
      #
      def authenticate(token)
        return gssapi.accept_context(token)
      end

      def display_name
        return gssapi.display_name
      end
    end
  end
end
