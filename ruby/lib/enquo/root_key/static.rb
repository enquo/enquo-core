module Enquo
	module RootKey
		class Static
			def self.new(k)
				unless k.is_a?(String)
					raise ArgumentError, "An Enquo static root key must be passed a string"
				end

				key = if k.encoding == Encoding::BINARY
					unless k.bytesize == 32
						raise ArgumentError, "An Enquo static root key must be a 32 byte binary string"
					end

					k
				else
					unless k =~ /\A\h{64}\z/
						raise ArgumentError, "An Enquo static root key must be a 64 byte hex string"
					end

					[k].pack("H*")
				end

				_new(key)
			end
		end
	end
end
