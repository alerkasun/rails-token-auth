module TokenAuth
  class AuthenticationToken < BaseToken
    expiration seconds: TokenAuth::auth_token_expire

    alias_method :touch, :expire_token
    public :touch
  end
end
