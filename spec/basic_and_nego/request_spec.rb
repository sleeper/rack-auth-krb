require 'spec_helper'
require 'basic_and_nego/request'
require 'base64'

describe BasicAndNego::Request do

  it "should be able to detect a no auth" do
    r = BasicAndNego::Request.new({})
    r.authenticator.should == BasicAndNego::Auth::None
  end

  it "should be able to detect a 'basic' scheme" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('fred:pass')}"})
    r.authenticator.should == BasicAndNego::Auth::Basic
  end

  it "should be able to detect a 'negotiate' scheme" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Negotiate #{Base64.encode64('fred:pass')}"})
    r.authenticator.should == BasicAndNego::Auth::Negotiate
  end

  it "should be able to detect an unsupported auth" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Digest #{Base64.encode64('fred:pass')}"})
    r.authenticator.should == BasicAndNego::Auth::Unsupported
  end

  it "should decode credentials" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('fred:pass')}"})
    r.credentials.should =~ ["fred", "pass"]
  end

  it "should return username" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('fred:pass')}"})
    r.username.should == "fred"
  end

end
