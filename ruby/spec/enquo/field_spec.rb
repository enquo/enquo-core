require_relative "../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Field do
	let(:key) { SecureRandom.bytes(32) }
	let(:crypto) { Enquo::Crypto.new(key) }
	let(:collection) { "foo" }
	let(:field_name) { "bar" }
	let(:field) { crypto.field(collection, field_name) }

	describe "#encrypt_i64" do
		context "with a small positive integer" do
			let(:value) { 42 }
			let(:context) { "test" }
			let(:result) { field.encrypt_i64(value, context) }
			let(:json) { JSON.parse(result, symbolize_names: true) }
			let(:ore64v1) { json[:ORE64v1] }

			it "works" do
				expect { result }.to_not raise_error
			end

			it "returns a string" do
				expect(result).to be_a(String)
			end

			it "returns a JSON string" do
				expect { json }.to_not raise_error
			end

			it "returns a JSON hash" do
				expect(json).to be_a(Hash)
			end

			it "contains an ORE64v1 value" do
				expect(json).to have_key(:ORE64v1)
			end

			it "has a ciphertext" do
				expect(ore64v1).to have_key(:ct)
			end

			it "has an IV" do
				expect(ore64v1).to have_key(:iv)
			end

			it "has an ORE ciphertext" do
				expect(ore64v1).to have_key(:ore)
			end
		end
	end

	describe "#decrypt_i64" do
		context "with a small positive integer" do
			let(:value) { 42 }
			let(:context) { "test" }
			let(:ciphertext) { field.encrypt_i64(value, context) }
			let(:plaintext) { field.decrypt_i64(ciphertext, context) }

			it "works" do
				expect { plaintext }.to_not raise_error
			end

			it "returns the original value" do
				expect(plaintext).to eq(value)
			end
		end
	end
end
