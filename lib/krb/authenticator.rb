require 'gssapi'
require 'base64'

module Krb
  class Authenticator
    attr_reader :env, :service, :realm, :keytab, :gssapi
    attr_reader :client_name, :logger
    attr_reader :request, :response, :headers

    def initialize(request, service, realm, keytab, logger)
      @request = request
      @service = service
      @realm = realm
      @keytab = keytab
      @headers = {}
      @client_name = nil
      @logger = logger
    end

    def authenticate
      unless request.provided?
        logger.debug "No authorization key provided: asking for one (401)"
        @response = unauthorized
        return false
      end

      setup_gssapi( @service )

      if !gssapi.acquire_credentials
        logger.debug "Unable to acquire credentials (500)"
        response = error
        return false
      end

      if request.negotiate?
        logger.debug "Negotiate scheme proposed by client"
        if !negotiate(request)
          logger.debug "Unable to authenticate (401)"
          response = unauthorized
          return false
        end
        @client_name = gssapi.display_name
      elsif request.basic?
        logger.debug "Basic scheme proposed by client"
        user, password = request.credentials
        puts "FRED: Basic auth user=#{user} pass=#{password}"
        # TODO: Play with Kerberos to authenticate user
      else
        response = bad_request
        return false
      end
      true
    end

    private

    def setup_gssapi(service)
      @gssapi = GSSAPI::Simple.new(@realm, service, @keytab)
    end

    def acquire_credentials
      return false if gssapi.nil?

      acquired = false
      begin
        gssapi.acquire_credentials
        acquired = true
      rescue GSSAPI::GssApiError => e
        logger.error "Unable to acquire credentials: #{e.message}"
      end
      acquired
    end

    def accept_token( tok )
      otok = nil
      begin
        otok = gssapi.accept_context(tok)
      rescue GSSAPI::GssApiError => e
        logger.error "Unable to validate token: #{e.message}"
      end
      otok
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

    def challenge(hash={})
      "Negotiate"
    end

    def unauthorized(www_authenticate = challenge)
      return [ 401,
        { 'Content-Type' => 'text/plain',
          'Content-Length' => '0',
          'WWW-Authenticate' => www_authenticate.to_s },
          []
      ]
    end

    def bad_request
      return [ 400,
        { 'Content-Type' => 'text/plain',
          'Content-Length' => '0' },
          []
      ]
    end

    def error
      return [ 500,
        { 'Content-Type' => 'text/plain',
          'Content-Length' => '0' },
          []
      ]
    end


  end
end
