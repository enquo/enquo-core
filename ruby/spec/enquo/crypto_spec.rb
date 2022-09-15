require_relative "../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Crypto do
	let(:crypto) { Enquo::Crypto.new(key) }

	context "with a valid key" do
		let(:key) { SecureRandom.bytes(32) }

		it "loads successfully" do
			expect { crypto }.to_not raise_error
		end

		it "generates a field" do
			expect { crypto.field("foo", "bar") }.to_not raise_error
		end
	end

	{
		"a text string key" => "ohai" * 8,
		"a short key"       => SecureRandom.bytes(8),
		"a long key"        => SecureRandom.bytes(64),
		"a random object"   => Object.new,
	}.each do |desc, input|
		context "with #{desc}" do
			let(:key) { input }

			it "assplodes" do
				expect { crypto }.to raise_error(ArgumentError)
			end
		end
	end
end
