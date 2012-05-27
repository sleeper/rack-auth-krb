module BasicAndNego
  module Auth
    module Responses

      def challenge
        ["Negotiate", "Basic"]
      end

      def unauthorized
        return [ 401,
          { 'Content-Type' => 'text/plain',
            'Content-Length' => '0',
            'WWW-Authenticate' => challenge },
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
end
