require "date"

module Enquo
	class Field
		def self.new(*_)
			raise RuntimeError, "Enquo::Field cannot be instantiated directly; use Enquo::Crypto#field instead"
		end

		def encrypt_i64(i, ctx, safety: true, no_query: false)
			unless i.is_a?(Integer)
				raise ArgumentError, "Enquo::Field#encrypt_i64 can only encrypt integers"
			end

			unless i >= -2 ** 63 || i < 2 ** 63
				raise ArgumentError, "Enquo::Field#encrypt_i64 can only encrypt integers between -2^63 and 2^63-1 (got #{i})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_encrypt_i64(i, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_i64(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt from a string (got #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_decrypt_i64(data, ctx)
		end

		def encrypt_date(d, ctx, safety: true, no_query: false)
			unless d.is_a?(Date)
				raise ArgumentError, "Enquo::Field#encrypt_date can only encrypt Dates"
			end

			unless d.year >= -2 ** 15 && d.year < 2 ** 15 - 1
				raise RangeError, "Enquo::Field#encrypt_date can only encrypt dates where the year is between -32,768 and 32,767 (got #{d.year})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_encrypt_date(d.year, d.month, d.day, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_date(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt from a string (got #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_decrypt_date(data, ctx)
		end
	end
end
