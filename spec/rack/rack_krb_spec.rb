require 'spec_helper'
require 'rack/auth/krb/basic_and_nego'
require 'basic_and_nego/nulllogger'

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

  before(:each) do
    @basic_app = lambda{|env| [200,{'Content-Type' => 'text/plain'},'OK']}
    @env = env_with_params("/", {}, {'rack.logger' => BasicAndNego::NullLogger.new})
  end

  it "should return a 401 if authentication failed" do
    app = setup_rack(@basic_app)
    p = double("processor").as_null_object
    p.should_receive(:response).twice.and_return(not_authorized_response)
    p.should_receive(:process_request)
    ::BasicAndNego::Processor.should_receive(:new).and_return(p)

    app.call(@env).first.should == 401
  end

  it "should not ask for authentication if client is already authenticated" do
    app = setup_rack(@basic_app, {:session => SessionAuthentified})
    app.call(@env).first.should == 200

  end
end
