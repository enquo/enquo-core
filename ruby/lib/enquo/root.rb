module Enquo
	class Root
		def self.new(key)
			unless key.is_a?(String)
				raise ArgumentError, "key provided to Enquo::Root.new must be a string (got a #{key.class})"
			end

			unless key.encoding == Encoding::BINARY
				raise ArgumentError, "key provided to Enquo::Root.new must be a binary string (got a string encoded as #{key.encoding})"
			end

			unless key.bytesize == 32
				raise ArgumentError, "key provided to Enquo::Root.new must be a 32 byte binary string (got #{key.bytesize} bytes)"
			end

			_new(key)
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
