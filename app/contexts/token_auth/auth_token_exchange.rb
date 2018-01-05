class TokenAuth::AuthTokenExchange
  include DCI::Context

  attr_reader :token, :listener

  def initialize(code, listener)
    @listener = listener
    @token = TokenAuth::ExchangeToken.find(code)
    @entity = @token.entity
  end

  def perform
    in_context do
      @token.destroy_token
      session = @entity.create_authentication

      listener.token_exchange_succeed(session)
    end
  end
end
