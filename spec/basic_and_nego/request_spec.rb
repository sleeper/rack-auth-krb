require 'spec_helper'
require 'basic_and_nego/request'
require 'base64'

describe BasicAndNego::Request do
  it "should be able to detect a 'basic' scheme" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('fred:pass')}"})
    r.should be_basic
  end

  it "should be able to detect a 'negotiate' scheme" do
    r = BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Negotiate #{Base64.encode64('fred:pass')}"})
    r.should be_negotiate
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
