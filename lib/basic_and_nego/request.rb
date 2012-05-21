require 'rack/auth/abstract/request'
module BasicAndNego
  class Request < Rack::Auth::AbstractRequest
    attr_reader :credentials

    def basic?
      :basic == scheme
    end

    def negotiate?
      :negotiate == scheme
    end

    def credentials
      @credentials ||= params.unpack("m*").first.split(/:/, 2)
    end

    def username
      credentials.first
    end 
  end
end
