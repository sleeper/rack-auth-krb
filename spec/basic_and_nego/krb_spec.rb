require 'spec_helper'
require 'basic_and_nego/krb'

describe BasicAndNego::Krb do
  let(:logger) { double('logger').as_null_object }
  let(:realm) {"my realm"}
  let(:keytab) {"my keytab"}

  it "should initialize" do
    krb = BasicAndNego::Krb.new(logger, realm, keytab)
    krb.realm.should == realm
  end

  it "should authenticate user/password" do
    user = "fred"
    passwd = "passwd"
    k = double("rkerberos").as_null_object
    k.should_receive(:get_init_creds_password).with(user, passwd).and_return(true)
    Kerberos::Krb5.should_receive(:new).and_yield(k)
    krb = BasicAndNego::Krb.new(logger, realm, keytab)
    krb.authenticate(user, passwd).should be_true
  end

  it "should catch exception from underlying system" do
    user = "fred"
    passwd = "passwd"
    k = double("rkerberos").as_null_object
    k.should_receive(:get_init_creds_password).with(user, passwd).and_raise(Kerberos::Krb5::Exception)
    Kerberos::Krb5.should_receive(:new).and_yield(k)
    krb = BasicAndNego::Krb.new(logger, realm, keytab)
    krb.authenticate(user, passwd).should be_false
  end
end
