require 'rails_helper'

module TestTokenAuthenticable
  class Authenticable
    def self.before_save(*args)
    end

    include TokenAuth::Authenticatable
  end
end
