module TokenAuth
  module RedisAdapter
    extend ActiveSupport::Concern

    class_methods do
      def get_hash(uid)
        Redis.current.hgetall(build_redis_key(uid)).symbolize_keys
      end

      def delete_key(uid)
        Redis.current.del(build_redis_key(uid))
      end

      def set_hash(uid, args = {})
        expiration = args.delete(:expiration)
        key = build_redis_key(uid)

        Redis.current.mapped_hmset(key, args)
        Redis.current.expire(key, expiration.to_i) if expiration.present?
      end

      def expire_key(uid, expiration)
        Redis.current.expire(build_redis_key(uid), expiration)
      end

      def key_exists(uid)
        Redis.current.exists(build_redis_key(uid))
      end

      def build_redis_key(uid)
        ['token_auth', self.name.parameterize.singularize.underscore, uid].join(':')
      end
    end
  end
end
