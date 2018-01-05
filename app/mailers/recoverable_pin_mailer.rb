class RecoverablePinMailer < TokenAuthMailer
  def reset_password_mail(email, token)
    @token = token
    mail(to: email, subject: "Reset password mail")
  end
end
