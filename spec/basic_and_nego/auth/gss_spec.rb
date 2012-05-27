require 'spec_helper'
require 'basic_and_nego/auth/gss'

describe BasicAndNego::Auth::GSS do
  let(:realm) { "my realm"}
  let(:service) { "foo" }
  let(:keytab) { "my keytab" }
  let(:gssapi) { double("gss api").as_null_object }
  let(:logger) { double('logger').as_null_object }
  let(:good_request) { BasicAndNego::Request.new({'HTTP_AUTHORIZATION' => "Negotiate VGhpcyBpcyBteSB0b2tlbg=="})}

  it "should initialize and deal with gssapi" do
    gssapi.should_receive(:acquire_credentials)
    GSSAPI::Simple.should_receive(:new).with(realm, service, keytab).and_return(gssapi)
    g = BasicAndNego::Auth::GSS.new(logger, service, realm, keytab)
  end

  it "should authenticate request" do
    gssapi.should_receive(:acquire_credentials)
    gssapi.should_receive(:accept_context).and_return("Granted")
    GSSAPI::Simple.should_receive(:new).with(realm, service, keytab).and_return(gssapi)
    g = BasicAndNego::Auth::GSS.new(logger, service, realm, keytab)
    g.authenticate("My token").should == "Granted"
  end

end

