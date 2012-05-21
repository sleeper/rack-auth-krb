require 'socket'
require 'basic_and_nego/request'
require 'basic_and_nego/gss'
require 'basic_and_nego/krb'
require 'base64'

module BasicAndNego
  class Logic
    attr_reader :env, :service, :realm, :keytab, :hostname
    attr_reader :client_name, :logger
    attr_reader :request, :response, :headers

    def initialize(env, logger, realm, keytab)
      @env = env
      @service = service
      @realm = realm
      @keytab = keytab
      @headers = {}
      @hostname = Socket::gethostname
      @service = service || "http@#{hostname}"

      @logger = logger
      @client_name = nil
      @request = BasicAndNego::Request.new(env)
    end

    def process_request
      session = env['rack.session']

      # If the user is not yet authenticated, or if
      # there's no session ... well we have to authenticate him
      if session.nil? || !session['REMOTE_USER']
        logger.debug "User not authenticated : delegate to Krb authenticator"

        if !authenticate
          return
        end

        env['REMOTE_USER'] = client_name
        if session
          session['REMOTE_USER'] = client_name
        end
      else
        logger.debug "User #{session['REMOTE_USER']} already authenticated"
        env['REMOTE_USER'] = session['REMOTE_USER']
      end
    end

    def authenticate
      unless request.provided?
        logger.debug "No authorization key provided: asking for one (401)"
        @response = unauthorized
        return false
      end

      if request.negotiate?
        logger.debug "Negotiate scheme proposed by client"
        return negotiate

      elsif request.basic?
        logger.debug "Basic scheme proposed by client"
        return basic

      else

        @response = bad_request
        return false
      end
      true
    end

    private

    def negotiate
      begin
        gss = BasicAndNego::GSS.new(service, realm, keytab)
      rescue GSSAPI::GssApiError => e
        logger.error "Unable to setup GSSAPI: #{e.message}"
        @response = error
        return false
      end

      if !gss.authenticate(request)
        logger.debug "Unable to authenticate (401)"
        @response = unauthorized
        return false
      end

      @client_name = gss.display_name
      true
    end

    def basic
      user, password = request.credentials
      krb = BasicAndNego::Krb.new(realm, keytab)

      if !krb.authenticate(user, password)
        logger.debug "Unable to authenticate (401)"
        @response = unauthorized
        return false
      end
      @client_name = user

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
