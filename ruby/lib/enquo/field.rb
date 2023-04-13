require "date"

module Enquo
	class Field
		def self.new(*_)
			raise RuntimeError, "Enquo::Field cannot be instantiated directly; use Enquo::Crypto#field instead"
		end

		def encrypt_boolean(b, ctx, safety: true, no_query: false)
			unless b.is_a?(TrueClass) || b.is_a?(FalseClass)
				raise ArgumentError, "Enquo::Field#encrypt_boolean can only encrypt booleans (got an instance of #{b.class})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_encrypt_boolean(b, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_boolean(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_boolean can only decrypt from a string (got an instance of #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_boolean can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_decrypt_boolean(data, ctx)
		end

		def encrypt_i64(i, ctx, safety: true, no_query: false)
			unless i.is_a?(Integer)
				raise ArgumentError, "Enquo::Field#encrypt_i64 can only encrypt integers (got an instance of #{i.class})"
			end

			unless i >= -2 ** 63 && i < 2 ** 63
				raise ArgumentError, "Enquo::Field#encrypt_i64 can only encrypt integers between -2^63 and 2^63-1 (got #{i})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_encrypt_i64(i, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_i64(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt from a string (got an instance of #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_i64 can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_decrypt_i64(data, ctx)
		end

		def encrypt_date(d, ctx, safety: true, no_query: false)
			unless d.is_a?(Date)
				raise ArgumentError, "Enquo::Field#encrypt_date can only encrypt Dates (got an instance of #{d.class})"
			end

			unless d.year >= -2 ** 15 && d.year < 2 ** 15 - 1
				raise RangeError, "Enquo::Field#encrypt_date can only encrypt dates where the year is between -32,768 and 32,767 (got #{d.year})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_encrypt_date(d.year, d.month, d.day, ctx, no_query ? :no_query : safety == :unsafe ? :unsafe : :default)
		end

		def decrypt_date(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt from a string (got an instance of #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_decrypt_date(data, ctx)
		end

		def encrypt_text(t, ctx, safety: true, no_query: false, order_prefix_length: nil)
			unless t.is_a?(String)
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt Strings (got an instance of #{t.class})"
			end

			unless [Encoding::UTF_8, Encoding::US_ASCII].include?(t.encoding)
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt UTF-8 strings (got a string encoding of #{t.encoding})"
			end

			unless t.valid_encoding?
				raise ArgumentError, "Enquo::Field#encrypt_string can only encrypt validly-encoded strings"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			unless order_prefix_length.nil?
				unless safety == :unsafe
					raise ArgumentError, "Ordering is only supported when the text field is marked unsafe"
				end

				unless order_prefix_length.is_a?(Integer)
					raise ArgumentError, "Ordering prefix length must be an integer (got an instance of #{order_prefix_length.class})"
				end

				unless (1..255).include?(order_prefix_length)
					raise ArgumentError, "Ordering prefix length must be between 1 and 255 inclusive (got #{order_prefix_length})"
				end
			end

			mode = if no_query
				:no_query
			elsif !order_prefix_length.nil?
				:orderable
			elsif safety == :unsafe
				:unsafe
			else
				:default
			end

			_encrypt_text(t, ctx, mode, order_prefix_length)
		end

		def decrypt_text(data, ctx)
			unless data.is_a?(String)
				raise ArgumentError, "Enquo::Field#decrypt_text can only decrypt from a string (got an instance of #{data.class})"
			end

			unless data.encoding == Encoding::UTF_8 && data.valid_encoding?
				raise ArgumentError, "Enquo::Field#decrypt_date can only decrypt validly-encoded UTF-8 strings (got #{data.encoding})"
			end

			unless ctx.is_a?(String)
				raise ArgumentError, "Encryption context must be a string (got an instance of #{ctx.class})"
			end

			_decrypt_text(data, ctx)
		end

		def encrypt_text_length_query(len)
			unless len.is_a?(Integer)
				raise ArgumentError, "Enquo::Field#encrypt_text_length_query can only encrypt integers (got an instance of #{len.class})"
			end

			unless len >= 0 && len < 2 ** 32
				raise ArgumentError, "Enquo::Field#encrypt_text_length_query can only encrypt integers between 0 and 2^32-1 (got #{len})"
			end

			_encrypt_text_length_query(len)
		end
	end
end
