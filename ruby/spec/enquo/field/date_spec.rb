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

	describe "#encrypt_date" do
		let(:ciphertext) { field.encrypt_date(value, context, **opts) }

		{
			"around now" => Date.new(2022, 9, 1),
			"a little while ago" => Date.new(1970, 1, 1),
			"a long time ago" => Date.new(1492, 12, 17),
			"a *really* long time ago" => Date.new(-4000, 1, 1),
			"not long enough in the future" => Date.new(2038, 1, 19),
			"a long time in the future" => Date.new(2106, 2, 7),
			"a *really* long time in the future" => Date.new(4096, 1, 1),
		}.each do |desc, input|
			context "with a date that is #{desc}" do
				let(:value) { input }

				it_behaves_like "an encrypt function"

				it "is a v1 value" do
					expect(json).to have_key(:v1)
				end

				it "contains ORE values" do
					expect(v1).to have_key(:y)
					expect(v1).to have_key(:m)
					expect(v1).to have_key(:d)
				end
			end
		end

		{
			"too long ago" => Date.new(-33_000, 1, 1),
			"too far in the future" => Date.new(33_000, 1, 1),
		}.each do |desc, input|
			context "with a date that is #{desc}" do
				let(:value) { input }

				it "assplodes with RangeError" do
					expect { ciphertext }.to raise_error(RangeError)
				end
			end
		end

		{
			"an integer" => 42,
			"a float" => 4.2,
			"a string" => "ohai!",
			"a boolean" => true,
			"nil" => nil,
			"a random object" => Object.new,
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it "assplodes with TypeError" do
					expect { ciphertext }.to raise_error(TypeError)
				end
			end
		end
	end

	describe "#decrypt_date" do
		let(:decryption_context) { context }
		let(:ciphertext) { field.encrypt_date(value, context) }
		let(:plaintext) { field.decrypt_date(ciphertext, decryption_context) }

		it_behaves_like "a decrypt function", Date.today

		{
			"around now" => Date.new(2022, 9, 1),
			"a little while ago" => Date.new(1970, 1, 1),
			"a long time ago" => Date.new(1492, 12, 17),
			"a *really* long time ago" => Date.new(-4000, 1, 1),
			"not long enough in the future" => Date.new(2038, 1, 19),
			"a long time in the future" => Date.new(2106, 2, 7),
			"a *really* long time in the future" => Date.new(4096, 1, 1),
		}.each do |desc, input|
			context "with a recent date" do
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
