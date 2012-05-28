module BasicAndNego
  module Auth
    module Responses

      def challenge
        ["Negotiate", "Basic"]
      end

      def unauthorized
        [ 401,
          { 'Content-Type' => 'text/plain',
            'Content-Length' => '0',
            'WWW-Authenticate' => challenge },
            []
        ]
      end

      def bad_request
        [ 400,
          { 'Content-Type' => 'text/plain',
            'Content-Length' => '0' },
            []
        ]
      end

      def error
        [ 500,
          { 'Content-Type' => 'text/plain',
            'Content-Length' => '0' },
            []
        ]
      end

    end
  end
end
