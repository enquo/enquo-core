begin
	require 'git-version-bump'
rescue LoadError
	nil
end

Gem::Specification.new do |s|
	s.name = "enquo-core"

	s.version = ENV.fetch("GVB_VERSION_OVERRIDE") { GVB.version rescue "0.0.0.1.NOGVB" }
	s.date    = GVB.date    rescue Time.now.strftime("%Y-%m-%d")

	s.platform = Gem::Platform::RUBY

	s.summary  = "Core library for encrypted querying operations"

	s.authors  = ["Matt Palmer"]
	s.email    = ["matt@enquo.org"]
   s.homepage = "https://enquo.org/active_enquo"

	s.metadata["homepage_uri"] = s.homepage
	s.metadata["source_code_uri"] = "https://github.com/enquo/enquo-core"
	s.metadata["changelog_uri"] = "https://github.com/enquo/enquo-core/releases"
	s.metadata["bug_tracker_uri"] = "https://github.com/enquo/enquo-core/issues"

	s.files = `git ls-files -z`.split("\0").reject { |f| f =~ /^(G|spec|Rakefile)/ }
	s.extensions = ["ext/enquo/extconf.rb"]

	s.required_ruby_version = ">= 2.7.0"

	s.add_runtime_dependency 'rb_sys', '~> 0.1'

	s.add_development_dependency 'bundler'
	s.add_development_dependency 'github-release'
	s.add_development_dependency 'rake', '~> 13.0'
	s.add_development_dependency 'rake-compiler', '~> 1.2'
	s.add_development_dependency 'rake-compiler-dock', '~> 1.2'
	s.add_development_dependency 'redcarpet'
	s.add_development_dependency 'rspec'
	s.add_development_dependency 'simplecov'
	s.add_development_dependency 'yard'
end
