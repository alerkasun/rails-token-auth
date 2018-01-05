module TokenAuth
  class PasswordRecoveryToken < BaseToken

    expiration seconds: TokenAuth::recovery_token_expire

    def generate!
      generate_token
      set_token
      set_inversed_token
    end

    def destroy
      @token = read_token(entity.id) if token.blank?
      if !!@token
        destroy_token
        destroy_inversed_token
      end
    end

    private

    def generate_token
      begin
        case TokenAuth::recover_tokenize_method
        when :pin
          @token = TokenAuth::password_recover_token_length.times.map { Random.new.rand(0..9) }.join
        when :urlsafe_base64
          @token = SecureRandom.urlsafe_base64(TokenAuth::password_recover_token_length)
        else
          raise UnknownTokenizeMethod
        end
      end while token_exists
    end
  end
end
