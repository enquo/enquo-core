module Enquo
	class Root
		def self.new(key)
			case key
			when RootKey::Static
				_new_from_static_root_key(key)
			else
				raise ArgumentError, "key must be a root key provider object (got a #{key.class})"
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
