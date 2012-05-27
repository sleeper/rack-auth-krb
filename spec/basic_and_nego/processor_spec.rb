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
    a.authenticate
    a.response.should_not be_nil
    a.response[0].should == 401
  end

  describe "GSS authentication" do 
    before(:each) do 
      env = {'HTTP_AUTHORIZATION' => "Negotiate VGhpcyBpcyBteSB0b2tlbg=="}
      env['rack.session'] = {}
      @a = BasicAndNego::Processor.new(env, BasicAndNego::NullLogger.new, 'my realm', 'my keytab file', nil)
      @gss = double('gss').as_null_object
    end

    it "should try authentication against GSS in case of Negotiate" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_return("Granted")
      @a.authenticate
    end

    it "should return 'unauthorized' if authentication fails" do 
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_return(nil)
      @a.authenticate.should be_false
      @a.response.should_not be_nil
      @a.response[0].should == 401
    end

    it "should return true if authentication worked" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_return("Granted")
      @a.authenticate.should be_true
      @a.response.should be_nil
    end

    it "should set client's name if authentication worked" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_return("Granted")
      @gss.should_receive(:display_name).and_return("fred")
      @a.authenticate.should be_true
      @a.client_name.should == "fred"
    end

    it "should set header to returned token if authentication worked" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_return("Granted")
      @gss.should_receive(:display_name).and_return("fred")
      @a.authenticate.should be_true
      @a.client_name.should == "fred"
      @a.headers['WWW-Authenticate'].should == "Negotiate #{Base64.strict_encode64('Granted')}"
    end

    it "should catch GSSAPI exceptions in getting credentials" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_raise(GSSAPI::GssApiError)
      @a.authenticate.should be_false
      @a.response.should_not be_nil
      @a.response[0].should == 500
    end

    it "should catch GSSAPI exceptions in authenticating token" do
      BasicAndNego::Auth::GSS.should_receive(:new).and_return(@gss)
      @gss.should_receive(:authenticate).and_raise(GSSAPI::GssApiError)
      @a.authenticate.should be_false
      @a.response.should_not be_nil
      @a.response[0].should == 401
    end
  end

  describe "Kerberos authentication" do
    before(:each) do 
      env = {'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('fred:pass')}"}
      env['rack.session'] = {}
      @realm = "my realm"
      @keytab = "my keytab"
      @logger = BasicAndNego::NullLogger.new
      @a = BasicAndNego::Processor.new(env, @logger, @realm, @keytab, nil)
      @krb = double('kerberos').as_null_object
      BasicAndNego::Auth::Krb.should_receive(:new).with(@logger, @realm, @keytab).and_return(@krb)
    end

    it "should try authentication against Kerberos in case of Basic" do
      @krb.should_receive(:authenticate).with("fred", "pass").and_return(true)
      @a.authenticate
    end

    it "should return 'unauthorized' if authentication fails" do 
      @krb.should_receive(:authenticate).and_return(false)
      @a.authenticate.should be_false
      @a.response.should_not be_nil
      @a.response[0].should == 401
    end

    it "should return true if authentication worked" do
      @krb.should_receive(:authenticate).and_return(true)
      @a.authenticate.should be_true
      @a.response.should be_nil
    end

    it "should set client's name if authentication worked" do
      @krb.should_receive(:authenticate).and_return(true)
      @a.authenticate.should be_true
      @a.client_name.should == "fred"
    end
  end
end
