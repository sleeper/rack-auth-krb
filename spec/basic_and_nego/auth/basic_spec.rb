require 'spec_helper'
require 'basic_and_nego/auth/basic'
require 'basic_and_nego/nulllogger'
require 'basic_and_nego/request'
require 'base64'

describe BasicAndNego::Auth::Basic do

  before(:each) do 
    env = {'HTTP_AUTHORIZATION' => "Basic #{::Base64.encode64('fred:pass')}"}
    @realm = "my realm"
    @keytab = "my keytab"
    @service = "http/hostname"
    @logger = BasicAndNego::NullLogger.new
    @request = BasicAndNego::Request.new(env)
    @request.should_receive(:credentials).and_return(['fred', 'pass'])
    @krb = double('kerberos').as_null_object
    BasicAndNego::Auth::Krb.should_receive(:new).with(@logger, @realm, @keytab).and_return(@krb)
    @a = BasicAndNego::Auth::Basic.new(@request, @logger, @realm, @keytab, @service)
  end

  it "should try authentication against Kerberos in case of Basic" do
    @krb.should_receive(:authenticate).with("fred", "pass").and_return(true)
    @a.process
  end

  it "should return 'unauthorized' if authentication fails" do 
    @krb.should_receive(:authenticate).and_return(false)
    @a.process
    @a.response.should_not be_nil
    @a.response[0].should == 401
  end

  it "should return true if authentication worked" do
    @krb.should_receive(:authenticate).and_return(true)
    @a.process
    @a.response.should be_nil
  end

  it "should set client's name if authentication worked" do
    @krb.should_receive(:authenticate).and_return(true)
    @a.process
    @a.client_name.should == "fred"
  end

end
