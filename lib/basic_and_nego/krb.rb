require "rkerberos"

module BasicAndNego
  class Krb
    attr_reader :realm, :keytab, :logger

    def initialize(logger, realm, keytab)
      @logger = logger
      @realm = realm
      @keytab = keytab
    end

    def authenticate(user, passwd)
      Kerberos::Krb5.new do |krb5|
        successfull = false
        begin
          krb5.get_init_creds_password(user, passwd)
          successfull = true
        rescue Kerberos::Krb5::Exception => e
          logger.error "Failed to authenticate user '#{user}': #{e.message}"
        end
        successfull
      end
    end
  end
end
