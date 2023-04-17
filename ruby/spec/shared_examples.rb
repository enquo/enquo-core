shared_examples "an encrypt function" do
	it "works" do
		expect { ciphertext }.to_not raise_error
	end

	it "returns a string" do
		expect(ciphertext).to be_a(String)
	end

	it "returns a JSON string" do
		expect { json }.to_not raise_error
	end

	it "returns a JSON hash" do
		expect(json).to be_a(Hash)
	end

	it "has an AES value" do
		expect(v1).to have_key(:a)
	end

	it "has a key ID" do
		expect(v1).to have_key(:k)
		expect(v1[:k].length).to eq(4)
		expect(v1[:k]).to all be_between(0, 255)
	end

	{
		"an integer" => 42,
		"a float" => 4.2,
		"a string" => "ohai!",
		"nil" => nil,
		"a random object" => Object.new,
	}.each do |desc, input|
		context "with no_query passed #{desc}" do
			let(:opts) { { no_query: input } }

			it "assplodes" do
				expect { ciphertext }.to raise_error(TypeError)
			end
		end

		context "with unsafe passed #{desc}" do
			let(:opts) { { unsafe: input } }

			it "assplodes" do
				expect { ciphertext }.to raise_error(TypeError)
			end
		end
	end

	{
		"an integer" => 42,
		"a float" => 4.2,
		"a boolean" => true,
		"nil" => nil,
		"a random object" => Object.new,
	}.each do |desc, ctx|
		context "when passed #{desc} as a context" do
			let(:context) { ctx }

			it "assplodes" do
				expect { ciphertext }.to raise_error(TypeError)
			end
		end
	end
end

shared_examples "a decrypt function" do |valid_value|
	{
		"an integer" => 42,
		"a float" => 4.2,
		"a boolean" => true,
		"nil" => nil,
		"a random object" => Object.new,
	}.each do |desc, input|
		context "when passed #{desc}" do
			let(:ciphertext) { input }

			it "assplodes" do
				expect { plaintext }.to raise_error(TypeError)
			end
		end
	end

	{
		"a non-UTF8 string" => "\0\xff".force_encoding("BINARY"),
		"an invalid UTF8 string" => "\0\xff".force_encoding("UTF-8"),
	}.each do |desc, input|
		context "when passed #{desc}" do
			let(:ciphertext) { input }

			it "assplodes" do
				expect { plaintext }.to raise_error(EncodingError)
			end
		end
	end

	{
		"a non-JSON string" => "ohai!",
		"a JSON bool" => "true",
		"a JSON string" => "\"ohai!\"",
		"a JSON integer" => "42",
		"a JSON float" => "4.2",
		"a JSON null" => "null",
		"a JSON array" => "[true, \"ohai!\", 42, 4.2, null]",
		"a JSON object with the wrong keys" => '{"a":"b"}',
	}.each do |desc, input|
		context "when passed #{desc}" do
			let(:ciphertext) { input }

			it "assplodes" do
				expect { plaintext }.to raise_error(Enquo::Error)
			end
		end
	end

	context "with a different context" do
		let(:decryption_context) { "this is a context that should never be real, I hope" }
		let(:value) { valid_value }

		it "assplodes" do
			expect { plaintext }.to raise_error(Enquo::Error)
		end
	end
end
