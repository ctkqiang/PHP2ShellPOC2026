# frozen_string_literal: true

require_relative "test_helper"

class ReportTest < Minitest::Test
  def blocked_result
    scan_with do |uri, purpose, _requests|
      probe(uri, status: 403, headers: { "server" => "openresty" },
                 body: "<html><title>Blocked</title></html>", purpose: purpose)
    end
  end

  def vulnerable_result
    scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.1" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end
  end

  def render(result, format, **overrides)
    PHP2ShellPOC2026::Report.render(
      [result],
      options(format: format, **overrides),
      meta: { generated_at: "2026-10-24T00:00:00Z", profile: "standard" }
    )
  end

  def test_text_reports_blocked_honestly
    text = render(blocked_result, "text")
    assert_includes text, "FINDINGS"
    assert_includes text, "Bottom line"
    assert_includes text, "ASSESSMENT"
    assert_includes text, "NEXT ACTIONS"
    assert_includes text, "BLOCK"
    assert_includes text, "n/a"
    assert_includes text, "INCONCLUSIVE"
    assert_includes text, "unverified: 1"
  end

  def test_json_envelope
    payload = JSON.parse(render(blocked_result, "json"))
    assert_equal "3.0", payload["schema_version"]
    assert_equal "php2shell-poc2026", payload["tool"]["name"]
    assert_equal 1, payload["summary"]["unverified"]
    assert_equal 1, payload["summary"]["blocked"]
    result = payload["results"].values.first
    assert_equal "inconclusive", result["verdict"]["status"]
    assert_equal "blocked", result["verdict"]["reason_code"]
  end

  def test_compact_json_is_one_line
    text = render(blocked_result, "json", compact: true).sub(/\n\z/, "")
    refute_includes text, "\n"
    assert JSON.parse(text)
  end

  def test_markdown
    text = render(vulnerable_result, "markdown")
    assert_includes text, "# php2shell-poc2026 report"
    assert_includes text, "VULNERABLE"
    assert_includes text, "ATT&CK assessment path"
    assert_includes text, "Remediation"
  end

  def test_sarif
    payload = JSON.parse(render(blocked_result, "sarif"))
    assert_equal "2.1.0", payload["version"]
    run = payload["runs"].first
    assert_equal "php2shell-poc2026", run["tool"]["driver"]["name"]
    assert_equal "PHP2Shell.Unverified", run["results"].first["ruleId"]
    assert_equal "note", run["results"].first["level"]
  end

  def test_sarif_exposed_is_error
    payload = JSON.parse(render(vulnerable_result, "sarif"))
    result = payload["runs"].first["results"].first
    assert_equal "PHP2Shell.VulnerableInterpreter", result["ruleId"]
    assert_equal "error", result["level"]
  end

  def test_csv
    text = render(blocked_result, "csv")
    lines = text.lines
    assert_includes lines.first, "target,url,verdict"
    assert_equal 2, lines.size
    assert_includes lines.last, "INCONCLUSIVE"
    assert_includes lines.last, "blocked"
  end

  def test_ndjson
    lines = render(blocked_result, "ndjson").lines
    assert_equal 2, lines.size
    target_record = JSON.parse(lines.first)
    run_record = JSON.parse(lines.last)
    assert_equal "target", target_record["record_type"]
    assert_equal "run", run_record["record_type"]
    assert_equal 1, run_record["summary"]["unverified"]
  end

  def test_text_quiet_has_summary_but_no_per_target_block
    result = blocked_result
    text = PHP2ShellPOC2026::Report.render(
      [result],
      options(format: "text", quiet: true),
      meta: { generated_at: "2026-10-24T00:00:00Z" }
    )
    assert_includes text, "BLOCK"
    refute_includes text, "ATT&CK assessment path"
  end

  def test_text_exposed_shows_remediation_and_technical_detail
    text = render(vulnerable_result, "text")
    assert_includes text, "VULN"
    assert_includes text, "REMEDIATION"
    assert_includes text, "TECHNICAL DETAIL"
  end

  def test_text_verbose_expands_blocked_detail
    text = render(blocked_result, "text", verbose: true)
    assert_includes text, "Assessment detail:"
    assert_includes text, "TECHNICAL DETAIL"
  end
end
