module TokenAuth
  class ExchangeToken < BaseToken
    additional_field :auth_token
    expiration  seconds: TokenAuth::exchange_token_expire

    def destroy_token
      self.class.delete_key(@token)
      TokenAuth::AuthenticationToken.delete_key(auth_token)
    end
  end
end
