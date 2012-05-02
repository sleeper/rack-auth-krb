module Rack
  module Auth
    module Krb
      class Request < Auth::AbstractRequest
        attr_reader :credentials

        def basic?
          :basic == scheme
        end

        def negociate?
          :negociate == scheme
        end

        def credentials
          @credentials ||= params.unpack("m*").first.split(/:/, 2)
        end

        def username
          credentials.first
        end 
      end
    end
  end
end
