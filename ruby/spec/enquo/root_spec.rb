require_relative "../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Root do
	let(:root) { Enquo::Root.new(key) }

	context "with a static key" do
		let(:key) { Enquo::RootKey::Static.new(SecureRandom.bytes(32)) }

		it "loads successfully" do
			expect { root }.to_not raise_error
		end

		it "generates a field" do
			expect { root.field("foo", "bar") }.to_not raise_error
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
				expect { root }.to raise_error(ArgumentError)
			end
		end
	end
end
