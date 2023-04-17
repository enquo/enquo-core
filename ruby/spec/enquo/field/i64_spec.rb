require_relative "../../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Field do
	let(:key) { Enquo::RootKey::Static.new(SecureRandom.bytes(32)) }
	let(:root) { Enquo::Root.new(key) }
	let(:collection) { "foo" }
	let(:field_name) { "bar" }
	let(:field) { root.field(collection, field_name) }
	let(:context) { "test" }
	let(:opts) { {} }
	let(:json) { JSON.parse(ciphertext, symbolize_names: true) }
	let(:v1) { json[:v1] }

	describe "#encrypt_i64" do
		let(:ciphertext) { field.encrypt_i64(value, context, **opts) }

		{
			"zero" => 0,
			"a small positive integer" => 42,
			"a small negative integer" => -42,
			"a large positive integer" => 2**42,
			"a large negative integer" => -2**42,
			"the largest positive integer" => 2**63 - 1,
			"the largest negative integer" => -2**63,
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it_behaves_like "an encrypt function"

				it "is a v1 value" do
					expect(json).to have_key(:v1)
				end

				it "contains an ORE value" do
					expect(v1).to have_key(:o)
				end
			end
		end

		{
			"a slightly too large positive integer" => 2**63,
			"a much too large positive integer" => 2**420,
			"a slightly too large (small?) negative integer" => -2**63 - 1,
			"a much too large negative integer" => -2**420,
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it "assplodes with RangeError" do
					expect { ciphertext }.to raise_error(RangeError)
				end
			end
		end

		{
			"a string" => "ohai!",
			"a float" => 4.2,
			"a boolean" => true,
			"nil" => nil,
			"a random object" => Object.new
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it "assplodes with TypeError" do
					expect { ciphertext }.to raise_error(TypeError)
				end
			end
		end
	end

	describe "#decrypt_i64" do
		let(:decryption_context) { context }
		let(:ciphertext) { field.encrypt_i64(value, context) }
		let(:plaintext) { field.decrypt_i64(ciphertext, decryption_context) }

		it_behaves_like "a decrypt function", 0

		{
			"zero" => 0,
			"a small positive integer" => 42,
			"a small negative integer" => -42,
			"a large positive integer" => 2**42,
			"a large negative integer" => -2**42,
			"the largest positive integer" => 2**63 - 1,
			"the largest negative integer" => -2**63,
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it "works" do
					expect { plaintext }.to_not raise_error
				end

				it "returns the original value" do
					expect(plaintext).to eq(value)
				end
			end
		end
	end
end
