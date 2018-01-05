module TokenAuth
  class BaseToken
    include RedisAdapter
    attr_accessor :entity, :token

    def initialize(entity)
      @entity = entity
    end

    def generate!
      generate_token
      set_token
    end

    def destroy
      destroy_token
    end

    class << self
      attr_accessor :expiration_time_seconds,
                    :additional_fields,
                    :additional_fields_names

      def find(token)
        payload = get_hash(token)

        raise FindEntityException.new if payload.blank?

        entity_class = payload[:klass].classify.constantize

        handler = self.new entity_class.find(payload[:id])
        handler.token = token

        handler.class.additional_fields = payload.extract!(*handler.class.additional_fields_names)

        handler
      end

      def expiration(options = {})
        self.expiration_time_seconds = options[:seconds]
      end

      def additional_field(name)
        self.additional_fields ||= {}

        self.additional_fields_names ||= []
        self.additional_fields_names << name.to_sym

        define_method("#{name}=") do |val|
          self.class.additional_fields[name.to_sym] = val
        end

        define_method(name) do
          self.class.additional_fields[name.to_sym]
        end
      end
    end

    protected

    def generate_token
      begin
        @token = SecureRandom.hex
      end while token_exists
    end

    def read_token
      self.class.get_hash(@token)
    end

    def destroy_token
      self.class.delete_key(@token)
    end

    def destroy_inversed_token
      self.class.delete_key(@entity.id)
    end

    def expire_token
      self.class.expire_key(@token, self.class.expiration_time_seconds)
    end

    def token_exists
      self.class.key_exists(@token)
    end

    def set_token
      self.class.set_hash(@token, build_token)
    end

    def set_inversed_token
      self.class.set_hash(@entity.id, build_inversed_token)
    end

    private

    def build_token
      payload = {
        type: :_token,
        klass: @entity.class.name,
        id: @entity.id,
        expiration: self.class.expiration_time_seconds
      }

      if self.class.additional_fields.present?
        payload.merge!(self.class.additional_fields)
      end

      payload
    end

    def build_inversed_token
      {
        type: :_inversed_token,
        token: @token,
        expiration: self.class.expiration_time_seconds
      }
    end
  end
end
