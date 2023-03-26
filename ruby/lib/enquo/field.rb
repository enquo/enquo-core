require "date"

module Enquo
	class Field
		def self.new(*_)
			raise RuntimeError, "Enquo::Field cannot be instantiated directly; use Enquo::Crypto#field instead"
		end

		def encrypt_bool(b, ctx, safety: true, no_query: false)
			unless b.is_a?(TrueClass) || b.is_a?(FalseClass)
				raise ArgumentError, "Enquo::Field#encrypt_bool can only encrypt booleans"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_encrypt_bool(b, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_bool(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt from a string (got #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_decrypt_bool(data, ctx)
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

		def encrypt_text(t, ctx, safety: true, no_query: false)
			unless t.is_a?(String)
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt Strings"
			end

			unless t.encoding == Encoding::UTF_8
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt UTF-8 strings (got a string encoding of #{t.encoding})"
			end

			unless t.valid_encoding?
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt validly-encoded UTF-8 strings"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_encrypt_text(t, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_text(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_text can only decrypt from a string (got #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got a #{ctx.class})"
			end

			_decrypt_text(data, ctx)
		end
	end
end
