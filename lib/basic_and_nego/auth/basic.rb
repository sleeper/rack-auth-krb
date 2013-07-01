require 'basic_and_nego/auth/base'
require 'basic_and_nego/auth/krb'

module BasicAndNego
  module Auth
    class Basic < Base

      def initialize(request, logger, realm, keytab, service)
        super
        @krb = BasicAndNego::Auth::Krb.new(@logger, @realm, @keytab)
      end

      def process
        @logger.debug "Basic scheme proposed by client"
        user, password = @request.credentials
        authenticate(user, password)
        @client_name = user unless @response
      end

      private

      def authenticate(user, password)
        #We will firstly try to authenticate the user
        #suffixing his username with the realm If not already specified
        is_authenticated = false
        if !user.include?("@")
          user_domain = [user, "@", @realm].join
          is_authenticated = @krb.authenticate(user_domain, password)
          if !is_authenticated
            @logger.debug "Unable to authenticate #{user_domain}, trying with #{user}"
          end   
        end 
    
        #If authentication with suffix failed, try with user's given information  	
        if !is_authenticated
          unless @krb.authenticate(user, password)
            @logger.debug "Unable to authenticate (401)"
            @response = unauthorized
          end
        end
      end

    end
  end
end
