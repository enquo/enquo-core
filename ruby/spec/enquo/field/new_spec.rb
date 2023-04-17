require_relative "../../spec_helper"

require "enquo"

require "securerandom"

describe Enquo::Field do
	describe ".new" do
		it "doesn't exist" do
			expect { described_class.new }.to raise_error(NoMethodError)
		end
	end
end
