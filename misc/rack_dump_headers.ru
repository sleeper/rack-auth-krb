require 'rack/auth/krb/basic_and_nego'

infinity = Proc.new {|env| [200, {"Content-Type" => "text/html"}, env.inspect]}

use Rack::Auth::Krb::BasicAndNego, 'NCE.AMADEUS.NET', '/etc/krb5.keytab'

map '/' do
  run infinity
end

