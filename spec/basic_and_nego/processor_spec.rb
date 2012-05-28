require 'spec_helper'
require 'basic_and_nego/processor'
require 'basic_and_nego/nulllogger'

describe BasicAndNego::Processor do
  it "should not re-authenticate user" do
    env = {}
    env['rack.session'] = {}
    env['rack.session']['REMOTE_USER'] = 'fred'
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.process_request
    a.response.should be_nil
    a.headers.should be_empty
  end

  it "should try to authenticate if there's no session" do
    env = {}
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.should_receive(:authenticate)
    a.process_request
  end

  it "should set REMOTE_USER if user authenticated" do
    env = {}
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.should_receive(:authenticate).and_return(true)
    a.should_receive(:client_name).and_return("fred")
    a.process_request
    env['REMOTE_USER'].should == "fred"
  end

  it "should update the session if user authenticated" do
    env = {}
    env['rack.session'] = {}
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.should_receive(:authenticate).and_return(true)
    a.should_receive(:client_name).twice.and_return("fred")
    a.process_request
    env['REMOTE_USER'].should == "fred"
    env['rack.session']['REMOTE_USER'].should == 'fred'
  end

  it "should try to authenticate if user is not yet authenticated" do
    env = {}
    env['rack.session'] = {}
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.should_receive(:authenticate)
    a.process_request
  end

  it "should ask for an authorization key if none is provided" do
    env = {}
    env['rack.session'] = {}
    a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
    a.process_request
    a.response.should_not be_nil
    a.response[0].should == 401
  end

end
