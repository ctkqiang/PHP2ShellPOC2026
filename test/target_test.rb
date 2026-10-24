# frozen_string_literal: true

require_relative "test_helper"

class TargetTest < Minitest::Test
  def test_bare_hostname_defaults_to_https_and_root
    t = PHP2ShellPOC2026::Target.parse("example.com")
    assert_equal "https", t.scheme
    assert_equal "example.com", t.ascii_host
    assert_equal 443, t.port
    assert_equal "/", t.uri.path
    assert_equal "https://example.com/", t.display
  end

  def test_http_port_and_query_are_preserved
    t = PHP2ShellPOC2026::Target.parse("http://example.com:8080/a.php?x=1")
    assert_equal 8080, t.port
    assert_equal "/a.php", t.uri.path
    assert_equal "x=1", t.uri.query
    assert_equal "http://example.com:8080/a.php?x=1", t.display
  end

  def test_idn_is_punycoded_for_the_wire
    t = PHP2ShellPOC2026::Target.parse("https://münchen.example/")
    assert_equal "münchen.example", t.host
    assert_equal "xn--mnchen-3ya.example", t.ascii_host
    assert_equal "https://xn--mnchen-3ya.example/", t.uri.to_s
    assert t.international?
  end

  def test_ipv6_literal_with_port
    t = PHP2ShellPOC2026::Target.parse("https://[2001:db8::1]:8443/x")
    assert_equal "2001:db8::1", t.ascii_host
    assert_equal 8443, t.port
    assert_equal "https://[2001:db8::1]:8443/x", t.display
    assert t.ip?
  end

  def test_bare_ipv6_literal_is_wrapped
    t = PHP2ShellPOC2026::Target.parse("2001:db8::1")
    assert_equal "2001:db8::1", t.ascii_host
    assert_equal "https://[2001:db8::1]/", t.display
  end

  def test_credentials_in_url_are_rejected
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Target.parse("https://user:pass@example.com/")
    end
  end

  def test_non_http_scheme_is_rejected
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Target.parse("ftp://example.com/")
    end
  end

  def test_empty_target_is_rejected
    assert_raises(PHP2ShellPOC2026::UsageError) { PHP2ShellPOC2026::Target.parse("   ") }
  end

  def test_control_characters_are_rejected
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Target.parse("https://example.com/\nfoo")
    end
  end
end
