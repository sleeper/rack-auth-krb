require 'rubygems'

Gem::Specification.new do |gem|
  gem.name      = 'rack-auth-krb'
  gem.version   = '0.0.9'
  gem.authors   = ["Frederick Ros"]
  gem.email     = 'frederick.ros@gmail.com'
  gem.homepage  = 'https://github.com/sleeper/rack-auth-krb'
  gem.summary   = 'Kerberos/GSSAPI authentication (Basic and Negotiate) Rack library'
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- spec/*`.split("\n")

  gem.add_dependency "rack"
  gem.add_dependency "gssapi"
  gem.add_dependency "rkerberos"

  gem.add_development_dependency "rspec", "~> 2.0"
  gem.add_development_dependency "goliath"
  gem.add_development_dependency "puma"

  gem.extra_rdoc_files = ['README.md']

  gem.description = <<-EOF
  This library allows Kerberos/GSSAPI authentication using either Basic method
  or Negotiate (i.e. authentication without the need of user/password combo).
  EOF
end
