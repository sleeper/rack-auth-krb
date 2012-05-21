require 'spec_helper'
require 'basic_and_nego/gss'

describe BasicAndNego::GSS do

  it "should initialize and deal with gssapi" do
    realm = "my realm"
    service = "foo"
    keytab = "my keytab"
    gssapi = double("gss api").as_null_object
    gssapi.should_receive(:acquire_credentials)
    logger = double('logger').as_null_object
    GSSAPI::Simple.should_receive(:new).with(realm, service, keytab).and_return(gssapi)
    g = BasicAndNego::GSS.new(logger, service, realm, keytab)
  end
end

