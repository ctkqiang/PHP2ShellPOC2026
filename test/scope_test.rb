# frozen_string_literal: true

require_relative "test_helper"
require "tempfile"

class ScopeTest < Minitest::Test
  def target(value)
    PHP2ShellPOC2026::Target.parse(value)
  end

  def test_empty_scope_allows_everything
    decision = PHP2ShellPOC2026::Scope.empty.include?(target("https://example.com/"))
    assert decision.allowed
    assert_nil decision.pattern
  end

  def test_exact_domain_includes_subdomains
    scope = PHP2ShellPOC2026::Scope.parse(["example.com"])
    assert scope.include?(target("https://example.com/")).allowed
    assert scope.include?(target("https://api.example.com/")).allowed
    refute scope.include?(target("https://notexample.com/")).allowed
  end

  def test_wildcard_excludes_apex
    scope = PHP2ShellPOC2026::Scope.parse(["*.example.com"])
    assert scope.include?(target("https://api.example.com/")).allowed
    refute scope.include?(target("https://example.com/")).allowed
  end

  def test_cidr_and_ip
    scope = PHP2ShellPOC2026::Scope.parse(["192.0.2.0/24", "2001:db8::1"])
    assert scope.include?(target("https://192.0.2.55/")).allowed
    refute scope.include?(target("https://192.0.3.55/")).allowed
    assert scope.include?(target("https://[2001:db8::1]/")).allowed
    refute scope.include?(target("https://[2001:db8::2]/")).allowed
  end

  def test_url_line_extracts_host
    scope = PHP2ShellPOC2026::Scope.parse(["https://example.com/path"])
    assert scope.include?(target("https://api.example.com/")).allowed
  end

  def test_comments_and_blank_lines_are_ignored
    scope = PHP2ShellPOC2026::Scope.parse(["# comment", "", "example.com # inline"])
    assert_equal 1, scope.patterns.size
    assert scope.include?(target("https://example.com/")).allowed
  end

  def test_load_reads_file
    file = Tempfile.new("scope")
    file.write("# comment\nexample.com\n")
    file.close
    scope = PHP2ShellPOC2026::Scope.load(file.path)
    assert scope.include?(target("https://example.com/")).allowed
  ensure
    file&.unlink
  end

  def test_missing_scope_file_raises
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Scope.load("/no/such/scope/file")
    end
  end
end
