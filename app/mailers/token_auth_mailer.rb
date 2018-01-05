class TokenAuthMailer < ActionMailer::Base
  default from: TokenAuth::from_email
  layout 'token_auth_mailer'
end
