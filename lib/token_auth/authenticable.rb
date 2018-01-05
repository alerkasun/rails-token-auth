module TokenAuth
  module Authenticatable
    extend ActiveSupport::Concern

    included do
      before_save :hash_password
    end

    FIND_PATTER = 'find_by_%s!'.freeze

    module ClassMethods
      def authenticate(args)
        validate_credentials!(args)

        find_method = FIND_PATTER % class_variable_get(:@@credentials).join('_and_')

        begin
          entity = send(find_method, *perform_args(args))
          entity.create_authentication

        rescue Exception => exp
          raise Rails.env.production? ? Unauthorized : exp
        end
      end

      def generate_hash(password)
        Digest::SHA2.hexdigest(Digest::SHA2.hexdigest(TokenAuth::salt + password.to_s) +
                                TokenAuth::salt.reverse)
      end

      private

      def credentials(*args)
        class_variable_set(:@@credentials, args)
      end

      def perform_args(args)
        password_index = class_variable_get(:@@credentials).index(:password)
        return args unless password_index

        args[password_index] = generate_hash(args[password_index])
        args
      end

      def validate_credentials!(args)
        unless class_variable_get(:@@credentials).size == args.size
          raise BadCredentials.new("Wrong number of arguments.
            Get #{args.size} of #{class_variable_get(:@@credentials).size}")
        end

        raise BadCredentials.new("Params should not be blank!") if args.any?(&:blank?)
      end
    end

    def create_authentication
      Authentication.new(self)
    end

    def hash_password
      self.password = self.class.generate_hash(password) if password_changed?
    end
  end
end
