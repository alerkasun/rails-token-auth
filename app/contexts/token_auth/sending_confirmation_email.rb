class TokenAuth::SendingConfirmationEmail
  include DCI::Context

  attr_reader :entity, :email, :token_link, :listener

  def initialize(entity, email, token_link, listener = nil)
    @email, @listener, @token_link = email, listener, token_link
    @entity = entity.extend Confirmable
  end

  def perform
    in_context do
      begin
        token = entity.generate_confirmation_token
        entity.send_confirmation_email email, token

        listener.send_confirmation_email_complete
      rescue Exception => e
        listener.send_confirmation_email_error e
      end
    end
  end

  module Confirmable
    include DCI::ContextAccessor

    def generate_confirmation_token
      confirmation_token = TokenAuth::ConfirmationToken.new(self)
      confirmation_token.generate!
      confirmation_token.token
    end

    def send_confirmation_email(email, token)
      link = context.token_link.call token
      ConfirmationMailer.confirm_mail(email, link).deliver_later
    end
  end
end
