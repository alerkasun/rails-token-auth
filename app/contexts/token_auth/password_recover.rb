class TokenAuth::PasswordRecover
  include DCI::Context

  attr_reader :entity, :token, :listener, :recover_link

  def initialize(entity, listener, recover_link)
    @entity, @listener, @recover_link = entity, listener, recover_link
    @token = TokenAuth::PasswordRecoveryToken.new(entity)
  end

  def perform
    in_context do
      token.generate!
      send_mails
      listener.send_success
    end
  end

  def send_mails
    case TokenAuth::recover_method
    when :link
      link = @recover_link.call(token.code)
      RecoverableLinkMailer.reset_password_mail(entity.email, link).deliver_later
    when :pin
      RecoverablePinMailer.reset_password_mail(entity.email, token.code).deliver_later
    else
      raise UnknownRecoverMethod
    end
  end
end
