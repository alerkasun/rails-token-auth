module TokenAuth
  module Authenticator
    extend ActiveSupport::Concern

    included do
      private :authenticate_entity_by_token
      private :ensure_entity_authenticated!
    end

    def authenticate_entity_by_token
      @current_entity ||= authenticate_with_http_token do |token, options|
        @authentication = TokenAuth::AuthenticationToken.find(token)
        @authentication.entity
      end
    end

    def ensure_entity_authenticated!
      raise Unauthorized.new("Authenitcation failed") unless @current_entity.present?
      @authentication.touch
    end

    module ClassMethods
      def acts_as_token_authenticator_for(authenticable_class, options = {})
        authenticable_class_underscored = authenticable_class.name.parameterize.singularize.underscore

        before_action :"authenticate_#{authenticable_class_underscored}_by_token", options
        before_action :"ensure_#{authenticable_class_underscored}_authenticated!", options

        class_eval <<-AUTHENTICATOR, __FILE__, __LINE__ + 1
          def authenticate_#{authenticable_class_underscored}_by_token
            authenticate_entity_by_token
            @current_session = TokenAuth::Session.new(@authentication)
          end

          def ensure_#{authenticable_class_underscored}_authenticated!
            ensure_entity_authenticated!
          end

          def current_authenticated_entity
            @current_entity
          end

          def current_session
            @current_session
          end
        AUTHENTICATOR
      end

      def skip_acts_as_token_authenticator_for(authenticable_class, options = {})
        authenticable_class_underscored = authenticable_class.name.parameterize.singularize.underscore

        #skip_before_action :"authenticate_#{authenticable_class_underscored}_by_token", options
        # skip_before_action :"ensure_#{authenticable_class_underscored}_authenticated!", options
      end
    end
  end
end

ActionController::Base.send :include, TokenAuth::Authenticator
