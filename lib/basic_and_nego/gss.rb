module BasicAndNego
  class GSS
    def initialize(service, realm, keytab)
      @service = service
      @realm = realm
      @keytab = keytab 
#      setup_gssapi( @service )

#      if !gssapi.acquire_credentials
#        logger.debug "Unable to acquire credentials (500)"
#        response = error
#        return false
#      end

    end

    def setup_gssapi(service)
      @gssapi = GSSAPI::Simple.new(@realm, service, @keytab)
    end
  end
end
