class ConfirmationMailer < TokenAuthMailer
  def confirm_mail(email, link)
    @link = link
    mail(to: email, subject: "Confirm email")
  end
end
