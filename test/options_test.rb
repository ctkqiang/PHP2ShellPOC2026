# frozen_string_literal: true

require_relative "test_helper"

class OptionsTest < Minitest::Test
  def test_defaults_validate
    opts = PHP2ShellPOC2026::Options.new.validate!
    assert_equal "standard", opts.profile
    assert_equal "text", opts.format
    assert_equal 25, opts.max_requests
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
