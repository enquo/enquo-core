require_relative "../../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Field do
	let(:key) { Enquo::RootKey::Static.new(SecureRandom.bytes(32)) }
	let(:root) { Enquo::Root.new(key) }
	let(:collection) { "foo" }
	let(:field_name) { "bar" }
	let(:field) { root.field(collection, field_name) }
	let(:opts) { {} }
	let(:context) { "test" }
	let(:json) { JSON.parse(ciphertext, symbolize_names: true) }
	let(:v1) { json[:v1] }

	describe "#encrypt_text" do
		let(:ciphertext) { field.encrypt_text(value, context, **opts) }

		{
			"an empty string" => "",
			"a short string" => "ohai!",
			"a long string" => (["ohai!"] * 420).join("\n"),
		}.each do |desc, input|
			context "with #{desc}" do
				let(:value) { input }

				it_behaves_like "an encrypt function"

				it "is a v1 ciphertext" do
					expect(json).to have_key(:v1)
				end

				it "contains an equality key" do
					expect(v1).to have_key(:e)
				end

				it "contains a length" do
					expect(v1).to have_key(:l)
				end

				context "with no_query: true" do
					let(:opts) { { no_query: true } }

					it "does not contain an equality key" do
						expect(v1).to_not have_key(:e)
					end

					it "does not contain a length" do
						expect(v1).to_not have_key(:l)
					end
				end

				context "with unsafe: true" do
					let(:opts) { { unsafe: true } }

					it "contains a hash code" do
						expect(v1).to have_key(:h)
					end
				end

				context "with order_prefix_length" do
					context "that is valid" do
						let(:opts) { { order_prefix_length: 8, unsafe: true } }

						it "contains an ordering ciphertext" do
							expect(v1).to have_key(:o)
						end
					end

					context "and unsafe: false" do
						let(:opts) { { order_prefix_length: 8, unsafe: false } }

						it "assplodes" do
							expect { ciphertext }.to raise_error(ArgumentError)
						end
					end

					{
						"too big" => 500,
						"negative" => -1,
					}.each do |desc, input|
						context "that is #{desc}" do
							let(:opts) { { order_prefix_length: input, unsafe: true } }

							it "assplodes" do
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
						context "that is #{desc}" do
							let(:opts) { { order_prefix_length: input, unsafe: true } }

							it "assplodes" do
								expect { ciphertext }.to raise_error(TypeError)
							end
						end
					end
				end
			end
		end



		{
			"a non-UTF8 string" => "\0\xff".force_encoding("BINARY"),
			"an invalid UTF8 string" => "\0\xff".force_encoding("UTF-8"),
		}.each do |desc, input|
				context "with #{desc}" do
					let(:value) { input }

					it "assplodes with EncodingError" do
						expect { ciphertext }.to raise_error(EncodingError)
					end
				end
		end

		{
			"an integer" => 42,
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

	describe "#decrypt_text" do
		let(:decryption_context) { context }
		let(:ciphertext) { field.encrypt_text(value, context) }
		let(:plaintext) { field.decrypt_text(ciphertext, decryption_context) }

		it_behaves_like "a decrypt function", "ohai!"

		{
			"an empty string" => "",
			"a short string" => "ohai!",
			"a long string" => (["ohai!"] * 420).join("\n"),
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
