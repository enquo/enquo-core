module Enquo
	class Root
		def self.new(key)
			case key
			when RootKey::Static
				_new_from_static_root_key(key)
			else
				raise ArgumentError, "key must be a root key provider object (got a #{key.class})"
			end.tap do |k|
				# DIRTY HACK ALERT: take a reference to the key so it doesn't get GC'd
				# If someone can come up with a better way to acheive this, I'm all ears
				k.instance_variable_set(:@_key, key)
			end
		end

		def field(relation, name)
			if relation.is_a?(Symbol)
				relation = relation.to_s
			end

			if name.is_a?(Symbol)
				name = name.to_s
			end

			_field(relation, name)
		end
	end
end
