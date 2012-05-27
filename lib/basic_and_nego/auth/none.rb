module BasicAndNego
  module Auth
    class None < Base

      def process
        @logger.debug "No authorization key provided: asking for one (401)"
        @response = unauthorized
      end

    end
  end
end
