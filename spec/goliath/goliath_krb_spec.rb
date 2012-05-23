require 'spec_helper'
require 'goliath/rack/auth/krb/basic_and_nego'

describe Goliath::Rack::Auth::Krb::BasicAndNego do
  it 'accepts an app' do
    lambda { Goliath::Rack::Auth::Krb::BasicAndNego.new('my app', 'my realm', 'my keytab') }.should_not raise_error
  end

  describe 'with middleware' do
    before(:each) do
      @app = mock('app').as_null_object
      @env = Goliath::Env.new
      @env['CONTENT_TYPE'] = 'application/x-www-form-urlencoded; charset=utf-8'
      @auth = Goliath::Rack::Auth::Krb::BasicAndNego.new(@app, 'my realm', 'my keytab')
    end


    it 'returns status, headers and body from the app' do
      app_headers = {'Content-Type' => 'hash'}
      app_body = {:a => 1, :b => 2}
      l = double("logic").as_null_object
      l.should_receive(:response).and_return(nil)
      add_headers = {"fred" => "foo"}
      l.should_receive(:headers).and_return(add_headers)
      ::BasicAndNego::Logic.should_receive(:new).and_return(l)
      l.should_receive(:process_request)
      @app.should_receive(:call).and_return([200, app_headers, app_body])

      status, headers, body = @auth.call(@env)
      status.should == 200
      headers['fred'].should == "foo"
      body.should == app_body
    end

    it "returns error in case of failing authentication" do
      app_headers = {'Content-Type' => 'hash'}
      app_body = {:a => 1, :b => 2}
      l = double("logic").as_null_object
      r = [401, {}, "foo"]
      l.should_receive(:response).twice.and_return(r)
      l.should_receive(:process_request)
      ::BasicAndNego::Logic.should_receive(:new).and_return(l)

      response = @auth.call(@env)
      response.should =~ r
    end
  end
end
