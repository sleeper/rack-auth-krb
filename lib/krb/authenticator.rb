require 'gssapi'

module Krb
  class Authenticator
    attr_reader :env, :service, :realm, :keytab, :gssapi
    attr_reader :request, :response, :headers

    def initialize(request, service, realm, keytab)
      @request = request
      @service = service
      @realm = realm
      @keytab = keytab
    end

    def authenticate
      unless request.provided?
        @response = unauthorized
        return false
      end

      setup_gssapi( @service )

      if !gssapi.acquire_credentials
        response = error
        return false
      end

      if request.negotiate?
        if !negotiate(request)
          response = unauthorized
          return false
        end
      elsif request.basic?
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
        puts "FRED[ERROR]: #{e.message}"
      end
      acquired
    end

    def accept_token( tok )
      otok = nil
      begin
        otok = gssapi.accept_context(tok)
      rescue GSSAPI::GssApiError => e
        puts "FRED[ERROR]: #{e.message}"
      end
      otok
    end

    def negotiate(req)
      token = req.params
      puts "FRED: Negotiate auth token=#{token}"

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

  end
end
