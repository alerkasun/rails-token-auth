class TokenAuth::Session
  def initialize(authentication)
    @authentication = authentication
  end

  def token
    @authentication.token
  end

  def entity
    @authentication.entity
  end

  def destroy
    @authentication.destroy
  end
end
