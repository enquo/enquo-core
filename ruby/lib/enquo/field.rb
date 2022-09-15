module Enquo
	class Field
		def self.new(*_)
			raise RuntimeError, "Enquo::Field cannot be instantiated directly; use Enquo::Crypto#field instead"
		end

		def encrypt_i64(i, ctx)
			unless i.is_a?(Integer)
				raise ArgumentError, "Enquo::Field.encrypt_i64 can only encrypt integers"
			end

			unless i >= -2 ** 63 || i < 2 ** 63
				raise ArgumentError, "Enquo::Field.encrypt_i64 can only encrypt integers between -2^63 and 2^63-1 (got #{i})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_encrypt_i64(i, ctx)
		end

		def decrypt_i64(data, ctx)
			_decrypt_i64(data, ctx)
		end
	end
end
