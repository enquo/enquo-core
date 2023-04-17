require_relative "../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Root do
	let(:root) { Enquo::Root.new(key) }

	describe ".new" do
		describe "with a static key" do
			{
				"binary" => SecureRandom.bytes(32),
				"hex" => SecureRandom.hex(32).force_encoding("UTF-8"),
			}.each do |desc, input|
				context "in #{desc} form" do
					let(:key) { Enquo::RootKey::Static.new(input) }

					it "loads successfully" do
						expect { root }.to_not raise_error
					end

					it "generates a field" do
						expect { root.field("foo", "bar") }.to_not raise_error
					end
				end
			end

			it "handles the hex and binary key forms as equivalent" do
				binary_key_data = SecureRandom.bytes(32)
				hex_key_data = binary_key_data.unpack("H*").first

				binary_key = Enquo::RootKey::Static.new(binary_key_data)
				hex_key = Enquo::RootKey::Static.new(hex_key_data)

				expect(Enquo::Root.new(binary_key).field("foo", "bar").key_id)
					.to eq(Enquo::Root.new(hex_key).field("foo", "bar").key_id)
			end

			{
				"too short (binary)" => SecureRandom.bytes(16),
				"too long (binary)" => SecureRandom.bytes(64),
				"too short (hex)" => SecureRandom.hex(16).force_encoding("UTF-8"),
				"too long (hex)" => SecureRandom.hex(64).force_encoding("UTF-8"),
				"not a hex string" => "ohai" * 16,
				"hex in a binary encoded string" => SecureRandom.hex(32).force_encoding("BINARY"),
			}.each do |desc, input|
				context "generated from an input that is #{desc}" do
					it "assplodes with an ArgumentError" do
						expect { Enquo::RootKey::Static.new(input) }.to raise_error(ArgumentError)
					end
				end
			end

			{
				"hex in a rather unexpected encoded string" => SecureRandom.hex(32).force_encoding("Shift_JIS"),
			}.each do |desc, input|
				context "generated from an input that is #{desc}" do
					it "assplodes with an EncodingError" do
						expect { Enquo::RootKey::Static.new(input) }.to raise_error(EncodingError)
					end
				end
			end

			{
				"an integer" => 2**77 + 42,
				"a float" => 2.77,
				"a random object" => Object.new,
			}.each do |desc, input|
				context "generated from an input that is #{desc}" do
					it "assplodes" do
						expect { Enquo::RootKey::Static.new(input) }.to raise_error(TypeError)
					end
				end
			end
		end

		{
			"a text string" => "ohai" * 8,
			"an integer" => 42,
			"a float" => 4.2,
			"a random object"   => Object.new,
		}.each do |desc, input|
			context "with #{desc}" do
				let(:key) { input }

				it "assplodes" do
					expect { root }.to raise_error(TypeError)
				end
			end
		end
	end
end
