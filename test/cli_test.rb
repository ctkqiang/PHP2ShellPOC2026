# frozen_string_literal: true

require_relative "test_helper"
require "stringio"
require "tempfile"

class CliTest < Minitest::Test
  def run_cli(*args)
    old_out = $stdout
    old_err = $stderr
    $stdout = StringIO.new
    $stderr = StringIO.new
    code = PHP2ShellPOC2026::CLI.new(args).run
    [code, $stdout.string, $stderr.string]
  ensure
    $stdout = old_out
    $stderr = old_err
  end

  def run_cli_instance(*args)
    old_out = $stdout
    old_err = $stderr
    $stdout = StringIO.new
    $stderr = StringIO.new
    cli = PHP2ShellPOC2026::CLI.new(args)
    code = cli.run
    [cli, code, $stdout.string, $stderr.string]
  ensure
    $stdout = old_out
    $stderr = old_err
  end

  def test_dry_run_opens_no_socket
    code, out, err = run_cli("--dry-run", "https://192.0.2.10/")
    assert_equal 0, code
    assert_includes out, "dry-run request plan"
    assert_includes out, "GET https://192.0.2.10/"
    assert_empty err
  end

  def test_dry_run_json
    code, out, = run_cli("--dry-run", "--format", "json", "https://192.0.2.10/")
    assert_equal 0, code
    payload = JSON.parse(out)
    assert payload["dry_run"]
    assert_equal 1, payload["plans"].size
    assert_operator payload["plans"].first["requests"].size, :>, 0
  end

  def test_version
    code, out, = run_cli("--version")
    assert_equal 0, code
    assert_includes out, PHP2ShellPOC2026::VERSION
  end

  def test_help
    code, out, = run_cli("--help")
    assert_equal 0, code
    assert_includes out, "Usage: php2shell-poc2026"
    assert_includes out, "--fail-on"
    assert_includes out, "--lang"
    assert_includes out, "-en"
    assert_includes out, "-zh"
    assert_includes out, "--browser-ua"
  end

  def test_lang_flag_sets_text_locale
    cli, code, out, err = run_cli_instance("--dry-run", "--lang", "zh", "https://192.0.2.10/")
    assert_equal 0, code
    assert_empty err
    assert_equal "zh", cli.instance_variable_get(:@options).locale
    assert_includes out, "dry-run request plan"
  end

  def test_en_short_flag_sets_english_locale
    cli, code, _out, err = run_cli_instance("--dry-run", "-en", "https://192.0.2.10/")
    assert_equal 0, code
    assert_empty err
    assert_equal "en", cli.instance_variable_get(:@options).locale
  end

  def test_zh_short_flag_sets_chinese_locale
    cli, code, _out, err = run_cli_instance("--dry-run", "-zh", "https://192.0.2.10/")
    assert_equal 0, code
    assert_empty err
    assert_equal "zh", cli.instance_variable_get(:@options).locale
  end

  def test_short_language_flag_overrides_device_locale
    previous = ENV["PHP2SHELL_LANG"]
    ENV["PHP2SHELL_LANG"] = "zh_CN.UTF-8"
    cli, code, = run_cli_instance("--dry-run", "-en", "https://192.0.2.10/")
    assert_equal 0, code
    assert_equal "en", cli.instance_variable_get(:@options).locale
  ensure
    ENV["PHP2SHELL_LANG"] = previous
  end

  def test_browser_ua_flag_sets_compatibility_user_agent
    cli, code, _out, err = run_cli_instance("--dry-run", "--browser-ua", "https://192.0.2.10/")
    assert_equal 0, code
    assert_empty err
    opts = cli.instance_variable_get(:@options)
    assert opts.browser_ua
    assert_includes opts.user_agent, "Mozilla/5.0"
  end


  def test_lang_auto_detects_device_locale
    previous = ENV["PHP2SHELL_LANG"]
    ENV["PHP2SHELL_LANG"] = "zh_CN.UTF-8"
    cli, code, = run_cli_instance("--dry-run", "https://192.0.2.10/")
    assert_equal 0, code
    assert_equal "zh", cli.instance_variable_get(:@options).locale
  ensure
    ENV["PHP2SHELL_LANG"] = previous
  end

  def test_machine_formats_force_english_locale
    cli, code, out, err = run_cli_instance(
      "--dry-run", "--format", "json", "--lang", "zh", "https://192.0.2.10/"
    )
    assert_equal 0, code
    assert_empty err
    assert_equal "en", cli.instance_variable_get(:@options).locale
    assert_equal "en", JSON.parse(out)["options"]["locale"]
  end

  def test_require_scope_fails_closed_with_exit_4
    file = Tempfile.new("scope")
    file.write("example.com\n")
    file.close
    code, _out, err = run_cli("--dry-run", "--scope", file.path, "--require-scope", "https://192.0.2.10/")
    assert_equal 4, code
    assert_includes err, "scope violation"
  ensure
    file&.unlink
  end

  def test_out_of_scope_is_skipped_without_require_scope
    file = Tempfile.new("scope")
    file.write("example.com\n")
    file.close
    code, out, err = run_cli("--dry-run", "--scope", file.path, "https://192.0.2.10/")
    assert_equal 0, code
    assert_includes err, "skipping out-of-scope"
    assert_includes out, "0 targets"
  ensure
    file&.unlink
  end

  def test_config_targets_and_format
    file = Tempfile.new(["config", ".yml"])
    file.write(<<~YAML)
      profile: deep
      format: json
      targets:
        - https://192.0.2.10/
    YAML
    file.close
    code, out, err = run_cli("--config", file.path, "--dry-run")
    assert_equal 0, code
    payload = JSON.parse(out)
    assert_equal "deep", payload["options"]["profile"]
    assert_equal 1, payload["plans"].size
    assert_empty err
  ensure
    file&.unlink
  end

  def test_output_file
    outfile = Tempfile.new("report")
    outfile.close
    code, out, = run_cli("--dry-run", "--output", outfile.path, "https://192.0.2.10/")
    assert_equal 0, code
    assert_empty out
    assert_includes File.read(outfile.path), "dry-run request plan"
  ensure
    outfile&.unlink
  end

  def test_invalid_format_is_usage_error
    code, _out, err = run_cli("--dry-run", "--format", "yaml", "https://192.0.2.10/")
    assert_equal 1, code
    assert_includes err, "invalid argument"
  end

  def test_require_scope_without_scope_is_usage_error
    code, _out, err = run_cli("--dry-run", "--require-scope", "https://192.0.2.10/")
    assert_equal 1, code
    assert_includes err, "--require-scope needs --scope"
  end

  def test_dry_run_rejects_non_text_or_json
    code, _out, err = run_cli("--dry-run", "--format", "csv", "https://192.0.2.10/")
    assert_equal 1, code
    assert_includes err, "dry-run supports text or json"
  end

  def test_invalid_max_body_is_usage_error
    code, _out, err = run_cli("--dry-run", "--max-body", "512", "https://192.0.2.10/")
    assert_equal 1, code
    assert_includes err, "max-body"
  end
end
