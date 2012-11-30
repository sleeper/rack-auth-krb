rack-auth-krb
=============

Kerberos/GSSAPI authentication (Basic and Negotiate) rack middleware.

Actually this middleware should (hopefully) work for standard Rack
application and as a Goliath middleware.

Dependencies
============
Kerberos should be installed and configured on the server. 

If you do want to share the authentication through your application,
you'll need to have a Rack::Session middleware inserted before you in
the loop.

Rack applications
=================

```ruby
require 'rack/auth/krb/basic_and_nego'

infinity = Proc.new {|env| [200, {"Content-Type" => "text/html"}, ["Hello #{env['REMOTE_USER']}"]]}

use Rack::Session::Cookie
use Rack::Logger, ::Logger::DEBUG
use Rack::Auth::Krb::BasicAndNego, 'my realm', 'my keytab'

map '/' do
  run infinity
end
```


Goliath applications
====================

```ruby
require 'rack/session/cookie'
require 'goliath'
require 'goliath/rack/auth/krb/basic_and_nego'

class DumpHeaders < Goliath::API
  # Must be placed *before* BasicAndNego if we want it to use sessions !
  use Rack::Session::Cookie
  use Goliath::Rack::Auth::Krb::BasicAndNego, 'my realm', 'my keytab'

  def on_headers(env, headers)
    env.logger.info 'received headers: ' + headers.inspect
  end

  def response(env)
    [200, {}, "Hello #{env['REMOTE_USER']}"]
  end
end
```

Enable authentication only for a subset of paths
============
You can specify a list of paths for the ones you only want the authentication process to be enabled. 

```ruby
use Rack::Auth::Krb::BasicAndNego, 'my realm', 'my keytab', "http@hostname", ["/", "/oauth/authorize"]
```

or 

```ruby
use Goliath::Rack::Auth::Krb::BasicAndNego, 'my realm', 'my keytab', "http@hostname", ["/", "/oauth/authorize"]
```