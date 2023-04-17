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

	describe "#encrypt_boolean" do
		let(:ciphertext) { field.encrypt_boolean(value, context, **opts) }

		{
			"TrueValue" => true,
			"FalseValue" => false,
		}.each do |desc, input|
			context "with a #{desc}" do
				let(:value) { input }

				it_behaves_like "an encrypt function"

				it "is a v1 ciphertext" do
					expect(json).to have_key(:v1)
				end

				it "contains an ORE value" do
					expect(v1).to have_key(:o)
				end
			end
		end

		{
			"a string" => "ohai",
			"a integer" => 42,
			"a float" => 4.2,
			"nil" => nil,
			"a random object" => Object.new,
		}.each do |desc, input|
			let(:value) { input }

			context "with #{desc}" do
				it "assplodes" do
					expect { ciphertext }.to raise_error(TypeError)
				end
			end
		end
	end

	describe "#decrypt_boolean" do
		let(:decryption_context) { context }
		let(:ciphertext) { field.encrypt_boolean(value, context) }
		let(:plaintext) { field.decrypt_boolean(ciphertext, decryption_context) }

		it_behaves_like "a decrypt function", true

		{
			"TrueValue" => true,
			"FalseValue" => false,
		}.each do |desc, input|
			context "with an encrypted #{desc}" do
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
