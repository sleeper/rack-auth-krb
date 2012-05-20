$:.unshift File.expand_path(File.dirname(__FILE__) + '/../lib')
$:.unshift File.expand_path(File.dirname(__FILE__))

require 'rspec'
require 'rack'

def env_with_params(path = "/", params = {}, env = {})
  method = params.delete(:method) || "GET"
  env = { 'HTTP_VERSION' => '1.1', 'REQUEST_METHOD' => "#{method}" }.merge(env)
  Rack::MockRequest.env_for("#{path}?#{Rack::Utils.build_query(params)}", env)
end


def setup_rack(app = nil, opts={}, &block)
  app ||= block if block_given?

  Rack::Builder.new do
    use opts[:session] if opts[:session]
    use Rack::Auth::Krb::BasicAndNego, 'NCE.AMADEUS.NET', '/etc/krb5.keytab'
    run app
  end
end
