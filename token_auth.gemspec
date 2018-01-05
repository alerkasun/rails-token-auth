$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "token_auth/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "token_auth"
  s.version     = TokenAuth::VERSION
  s.authors     = ["Valeriy"]
  s.email       = ["sandulovve@gmail.com"]
  s.homepage    = "https://github.com/alerkasun"
  s.summary     = "Summary of TokenAuth."
  s.description = "Description of TokenAuth."
  s.license     = "MIT"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.rdoc"]
  s.test_files = Dir["spec/**/*"]

  s.add_dependency "rails", "~> 5.0.0.rc2"
  s.add_dependency "redis"

  s.add_development_dependency "sqlite3"

  s.add_development_dependency 'rspec-rails'
  s.add_development_dependency 'factory_girl_rails'
  s.add_development_dependency 'ffaker'
  s.add_development_dependency 'faker'
  s.add_development_dependency 'database_cleaner'
end
