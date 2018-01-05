Rails.application.routes.draw do

  mount TokenAuth::Engine => "/token_auth"
end
