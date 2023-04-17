require "bundler"
Bundler.setup(:default, :development)
require "rspec/core"
require "rspec/mocks"
require "json"

require_relative "./shared_examples"

RSpec.configure do |config|
	config.order = :random
	config.fail_fast = !!ENV["RSPEC_CONFIG_FAIL_FAST"]
	config.full_backtrace = !!ENV["RSPEC_CONFIG_FULL_BACKTRACE"]

	config.expect_with :rspec do |c|
		c.syntax = :expect
	end
end
