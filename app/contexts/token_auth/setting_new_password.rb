class TokenAuth::SettingNewPassword
  include DCI::Context

  attr_reader :password, :token, :entity_class, :listener

  def initialize(password, token, entity_class, listener)
    @password, @token, @entity_class, @listener = password, token, entity_class, listener
  end

  def perform
    in_context do
      @token = TokenAuth::PasswordRecoveryToken.find(token)
      token.delete
      token.entity.update!(password: password)
      listener.seting_new_password_success
    end
  end
end
