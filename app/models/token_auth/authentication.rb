class TokenAuth::Authentication

  attr_reader :entity, :auth, :exchange

  def initialize(entity)

    @entity = entity

    @auth = TokenAuth::AuthenticationToken.new(entity)
    auth.generate!

    @exchange = TokenAuth::ExchangeToken.new(entity)
    exchange.auth_token = auth.token
    exchange.generate!
  end

  def auth_token
    @auth.token
  end

  def exchange_token
    @exchange.token
  end
end
