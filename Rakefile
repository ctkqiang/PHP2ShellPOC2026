# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "lib" << "test"
  t.pattern = "test/**/*_test.rb"
  t.warning = false
end

desc "Build the gem"
task :build do
  sh "gem build php2shell_poc2026.gemspec"
end

desc "Run the CLI from the checkout"
task :run do
  sh "ruby -Ilib bin/php2shell-poc2026 --help"
end

task default: :test
