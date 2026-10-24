# frozen_string_literal: true

require_relative "lib/php2shell_poc2026/version"

Gem::Specification.new do |spec|
  spec.name     = "php2shell_poc2026"
  spec.version  = PHP2ShellPOC2026::VERSION
  spec.authors  = ["PHP2ShellPOC2026 Contributors"]
  spec.license  = "MIT"

  spec.summary       = "Passive PHP2Shell exposure analyzer and ATT&CK-mapped triage report"
  spec.description   = "Fingerprints the PHP interpreter behind a web endpoint, classifies edge blocks " \
                       "and soft-404s honestly, weighs exposure separately from exploit friction, maps " \
                       "findings onto MITRE ATT&CK and hands the blue team detection opportunities. " \
                       "Ordinary GET requests only — no payloads, no exploitation, safe to point at " \
                       "hosts you are authorized to assess."
  spec.homepage      = PHP2ShellPOC2026::HOMEPAGE
  spec.metadata = {
    "homepage_uri"          => spec.homepage,
    "source_code_uri"       => "#{spec.homepage}/tree/main",
    "changelog_uri"         => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri"       => "#{spec.homepage}/issues",
    "documentation_uri"     => "#{spec.homepage}/blob/main/README.md",
    "rubygems_mfa_required" => "true"
  }

  spec.required_ruby_version = ">= 2.7"
  spec.required_rubygems_version = ">= 3.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "bin/*",
    "docs/**/*.md",
    "README.md",
    "CHANGELOG.md",
    "LICENSE"
  ].reject { |path| File.directory?(path) }
  spec.bindir        = "bin"
  spec.executables   = ["php2shell-poc2026", "php2shell"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
