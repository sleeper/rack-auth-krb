require 'rack/auth/abstract/request'
module BasicAndNego
  class Request < Rack::Auth::AbstractRequest
    attr_reader :credentials

    def authenticator
      if !provided?
        BasicAndNego::Auth::None
      elsif supported_auth?
        BasicAndNego::Auth.const_get(scheme.to_s.capitalize)
      else
        BasicAndNego::Auth::Unsupported
      end
    end

    def credentials
      @credentials ||= params.unpack("m*").first.split(/:/, 2)
    end

    def username
      credentials.first
    end 

    private

    def supported_auth?
      [:basic, :negotiate].include? scheme
    end
  end
end
