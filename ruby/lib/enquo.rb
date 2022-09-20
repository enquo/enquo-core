module Enquo
	class Error < StandardError; end
end

begin
	RUBY_VERSION =~ /(\d+\.\d+)/
	require_relative "./#{$1}/enquo"
rescue LoadError
	begin
		require_relative "./enquo.#{RbConfig::CONFIG["DLEXT"]}"
	rescue LoadError
		raise LoadError, "Failed to load enquo.#{RbConfig::CONFIG["DLEXT"]}; either it hasn't been built, or was built incorrectly for your system"
	end
end

require_relative "./enquo/root"
require_relative "./enquo/field"
