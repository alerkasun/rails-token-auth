require "token_auth/engine"
require "token_auth/authenticable"
require "token_auth/authenticator"
require "token_auth/version"

module TokenAuth
  class Unauthorized < StandardError; end
  class BadCredentials < StandardError; end
  class UnknownRecoverMethod < StandardError; end
  class UnknownTokenizeMethod < StandardError; end
  class InvalidResetToken < StandardError; end
  class FindEntityException < StandardError; end

  @salt = '23JIUhui8*hg8y77%8h9h*78yG565^TF54%$ef6@93nid9fuu8*y7!34rf2!43r';
  @auth_token_expire = 2.hours
  @recovery_token_expire = 30.minutes
  @exchange_token_expire = 2.days
  @from_email = 'no-reply@template.com'
  @password_recover_token_length = 6
  @recover_method = :link
  @recover_tokenize_method = :urlsafe_base64

  class << self
    attr_accessor :salt, :auth_token_expire, :from_email, :recovery_token_expire,
                  :exchange_token_expire, :password_recover_token_length,
                  :recover_method, :recover_tokenize_method

    def setup
      yield self
    end
  end
end
