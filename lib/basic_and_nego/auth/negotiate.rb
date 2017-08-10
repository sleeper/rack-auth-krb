require 'basic_and_nego/auth/base'
require 'basic_and_nego/auth/gss'
require 'base64'

module BasicAndNego
  module Auth
    class Negotiate < Base

      def initialize(request, logger, realm, keytab, service)
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
        @gss = BasicAndNego::Auth::GSS.new(@logger, @service, @realm, @keytab)
      rescue GSSAPI::GssApiError => e
        @logger.error "Unable to setup GSSAPI: #{e.message}"
        @response = error
      end

      def authenticate
        token = ::Base64.strict_decode64(@request.params)
        @out_tok = @gss.authenticate(token)
      rescue GSSAPI::GssApiError => e
        @logger.error "Unable to authenticate: #{e.message}"
        @response = unauthorized_no_negotiate
      end

      def verify_token
        if !@out_tok
          @logger.debug "Unable to authenticate (401)"
          @response = unauthorized_no_negotiate
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
