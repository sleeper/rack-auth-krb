require 'spec_helper'
require 'rack/auth/krb/basic_and_nego'

class DummyApp
  def call(env)
    [200, {}, "Hello World"]
  end
end

class SessionAuthentified
  attr_accessor :app
  def initialize(app,configs = {})
    @app = app
  end

  def call(e)
    e['rack.session'] ||= {}
    e['rack.session']['REMOTE_USER'] = "fred"
    @app.call(e)
  end
end # session

describe "Rack::Auth::Krb::BasicAndNego" do
  OPTIONS = ['NCE.AMADEUS.NET', '/etc/krb5.keytab']

  before(:each) do
    @basic_app = lambda{|env| [200,{'Content-Type' => 'text/plain'},'OK']}
       @env = env_with_params("/")
  end

  it "should return a 401 if authentication failed" do
    app = setup_rack(@basic_app)
    auth = mock("krb auth").as_null_object
    auth.should_receive(:response).twice.and_return(not_authorized_response)
    BasicAndNego::Logic.should_receive(:new).and_return(auth)

    app.call(@env).first.should == 401
  end

  it "should not ask for authentication if client is already authenticated" do
    app = setup_rack(@basic_app, {:session => SessionAuthentified})
    app.call(@env).first.should == 200

  end
end
