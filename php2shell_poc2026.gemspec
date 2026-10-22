# frozen_string_literal: true

require_relative "lib/php2shell_poc2026/version"

Gem::Specification.new do |spec|
  spec.name     = "php2shell_poc2026"
  spec.version  = PHP2ShellPOC2026::VERSION
  spec.authors  = ["PHP2ShellPOC2026 Contributors"]
  spec.license  = "MIT"

  spec.summary       = "Passive PHP2Shell exposure analyzer"
  spec.description   = "Fingerprints the PHP interpreter behind a web endpoint, weighs the finding by " \
                       "deployment (SAPI, CDN/WAF), maps it onto the MITRE ATT&CK kill chain and hands " \
                       "the blue team detection opportunities. Ordinary GET requests only — no payloads, " \
                       "no exploitation, safe to point at hosts you are authorized to assess."

  spec.required_ruby_version = ">= 2.6"
  spec.files = Dir["lib/**/*.rb", "bin/*", "docs/**/*.md", "README.md", "LICENSE"]
  spec.bindir        = "bin"
  spec.executables   = ["php2shell-poc2026"]
  spec.require_paths = ["lib"]
end
