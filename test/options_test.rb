# frozen_string_literal: true

require_relative "test_helper"

class OptionsTest < Minitest::Test
  def test_defaults_validate
    opts = PHP2ShellPOC2026::Options.new.validate!
    assert_equal "standard", opts.profile
    assert_equal "text", opts.format
    assert_equal 25, opts.max_requests
    assert opts.interactive
    refute opts.yes
  end

  def test_invalid_profile
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(profile: "turbo").validate!
    end
  end

  def test_invalid_format
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(format: "yaml").validate!
    end
  end

  def test_invalid_fail_on
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(fail_on: "sometimes").validate!
    end
  end

  def test_invalid_threads
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(threads: 0).validate!
    end
  end

  def test_invalid_header
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(headers: { "X-Test" => "a\nb" }).validate!
    end
  end

  def test_invalid_path
    assert_raises(PHP2ShellPOC2026::UsageError) do
      PHP2ShellPOC2026::Options.new(paths: ["no-slash"]).validate!
    end
  end

  def test_locale_defaults_to_english
    assert_equal "en", PHP2ShellPOC2026::Options.new.locale
  end

  def test_browser_ua_uses_a_browser_compatible_user_agent
    opts = PHP2ShellPOC2026::Options.new(browser_ua: true)
    assert opts.browser_ua
    assert_includes opts.user_agent, "Mozilla/5.0"
    refute_includes opts.user_agent, "php2shell-poc2026"
  end

  def test_explicit_user_agent_wins_over_browser_ua
    opts = PHP2ShellPOC2026::Options.new(browser_ua: true, user_agent: "Custom/1.0")
    assert_equal "Custom/1.0", opts.user_agent
  end

  def test_locale_normalizes_chinese_variants
    assert_equal "zh", PHP2ShellPOC2026::Options.new(locale: "zh_CN.UTF-8").locale
    assert_equal "zh", PHP2ShellPOC2026::Options.new(locale: "zh-TW").locale
  end

  def test_unsupported_locale_falls_back_to_english
    assert_equal "en", PHP2ShellPOC2026::Options.new(locale: "fr_FR.UTF-8").locale
  end

  def test_public_h_redacts_secrets
    opts = PHP2ShellPOC2026::Options.new(
      cookie: "PHPSESSID=secret",
      bearer: "tok",
      basic_auth: "u:p",
      headers: { "Authorization" => "Bearer x", "X-Test" => "ok" }
    )
    public = opts.public_h
    assert_equal "***", public[:cookie]
    assert_equal "***", public[:bearer]
    assert_equal "***", public[:basic_auth]
    assert_equal "***", public[:headers]["Authorization"]
    assert_equal "ok", public[:headers]["X-Test"]
  end
end
