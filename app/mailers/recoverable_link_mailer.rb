class RecoverableLinkMailer < TokenAuthMailer
  def reset_password_mail(email, link)
    @link = link
    mail(to: email, subject: subject)
  end

  def subject
    ENV['APPLICATION_TITLE'] + 'reset password'
  end
end
