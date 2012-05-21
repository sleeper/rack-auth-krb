require 'gssapi'

module BasicAndNego
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

    def negotiate(req)
      token = req.params

      otok = accept_token(::Base64.strict_decode64(token.chomp))

      if otok.nil?
        return false
      end

      tok_b64 = ::Base64.strict_encode64(otok)
      headers['WWW-Authenticate'] = "Negotiate #{tok_b64}"
      return true
    end
  end
end
