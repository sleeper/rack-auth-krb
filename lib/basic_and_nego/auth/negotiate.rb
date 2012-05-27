require 'basic_and_nego/auth/gss'
require 'base64'

module BasicAndNego
  module Auth
    class Negotiate < Base

      def initialize(request, logger, realm, keytab)
        super
        setup_gss
      end

      def process
        @logger.debug "Negotiate scheme proposed by client"
        authenticate unless @response
        verify_token unless @response
        set_headers unless @response
      end

      private

      def setup_gss
        @gss = BasicAndNego::GSS.new(@logger, @service, @realm, @keytab)
      rescue GSSAPI::GssApiError => e
        @logger.error "Unable to setup GSSAPI: #{e.message}"
        @response = error
      end

      def authenticate
        token = ::Base64.strict_decode64(@request.params)
        @out_tok = @gss.authenticate(token)
      rescue GSSAPI::GssApiError => e
        @logger.error "Unable to authenticate: #{e.message}"
        @response = unauthorized
      end

      def verify_token
        if !@out_tok
          @logger.debug "Unable to authenticate (401)"
          @response = unauthorized
        end
      end

      def set_headers
        tok_b64 = ::Base64.strict_encode64(@out_tok)
        @headers = {'WWW-Authenticate' => "Negotiate #{tok_b64}"}
        @client_name = @gss.display_name
      end

    end
  end
end
