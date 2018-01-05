module TokenAuth
  class ConfirmationToken < BaseToken
    def generate!
      generate_token
      set_token
      set_inversed_token
    end

    def destroy
      destroy_token
      destroy_inversed_token
    end
  end
end
