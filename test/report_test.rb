# frozen_string_literal: true

require_relative "test_helper"

class ReportTest < Minitest::Test
  def blocked_result
    scan_with do |uri, purpose, _requests|
      probe(uri, status: 403, headers: { "server" => "openresty" },
                 body: "<html><title>Blocked</title></html>", purpose: purpose)
    end
  end

  def chinese_blocked_result
    scan_with(locale: "zh") do |uri, purpose, _requests|
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

  def ovhcloud_blocked_result
    scan_with do |uri, purpose, _requests|
      probe(uri, status: 403,
                 headers: { "server" => "openresty", "x-ovh-webhosting-id" => "abc123" },
                 body: "<html><title>Your request has been blocked - OVHcloud</title>" \
                       "<body>Request blocked due to suspicious activity.</body></html>",
                 purpose: purpose)
    end
  end

  def patched_result
    scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.35" }, purpose: purpose)
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

  def with_columns(value)
    old = ENV["COLUMNS"]
    ENV["COLUMNS"] = value.to_s
    yield
  ensure
    ENV["COLUMNS"] = old
  end

  def test_text_reports_blocked_honestly
    text = render(blocked_result, "text")
    assert_includes text, "FINDINGS"
    assert_includes text, "Bottom line"
    assert_includes text, "WHAT THIS MEANS"
    assert_includes text, "NEXT STEPS"
    assert_includes text, "UNKNOWN"
    assert_includes text, "blocked at the edge"
    assert_includes text, "0 of 3 pages responded normally"
    assert_includes text, "1 host:"
    assert_includes text, "3 requests"
    refute_includes text, "TECHNICAL DETAILS"
  end

  def test_answer_comes_before_the_table
    text = render(blocked_result, "text")
    assert_operator text.index("Bottom line"), :<, text.index("FINDINGS")
  end

  def test_verdicts_are_words_not_truncated_codes
    text = render(blocked_result, "text")
    assert_includes text, "UNKNOWN"
    refute_match(/\bINCON\b/, text)
  end

  def test_tips_only_advertise_unused_flags
    text = render(blocked_result, "text", verbose: true, toolchain: true, redteam: true)
    refute_includes text, "-v for full"
    refute_includes text, "-c for the toolchain"
    refute_includes text, "-r for red-team"
    assert_includes text, "--format json"
  end

  def test_toolchain_is_compact_by_default_and_explained_in_full_mode
    compact = render(blocked_result, "text", toolchain: true)
    refute_includes compact, "CT logs routinely expose the real origin"
    assert_includes compact, "curl — "

    full = render(blocked_result, "text", toolchain: true, toolchain_full: true)
    assert_includes full, "CT logs routinely expose the real origin"
  end

  def test_attack_assessment_path_has_no_duplicate_techniques
    ids = blocked_result.assessment_path.map(&:id)
    assert_equal ids.uniq, ids
  end

  def test_next_actions_default_to_the_short_list
    text = render(blocked_result, "text")
    assert_includes text, "1. Verify the response from your own egress"
    assert_includes text, "2. Retry with a browser-compatible User-Agent"
    refute_includes text, "Re-run from an approved proxy or egress"

    verbose = render(blocked_result, "text", verbose: true)
    assert_includes verbose, "Re-run from an approved proxy or egress"
    assert_includes verbose, "Enforce scope on the next run"
  end

  def test_json_envelope
    payload = JSON.parse(render(blocked_result, "json"))
    assert_equal "3.0", payload["schema_version"]
    assert_equal "php2shell-poc2026", payload["tool"]["name"]
    assert_equal 1, payload["summary"]["unverified"]
    assert_equal 1, payload["summary"]["blocked"]
    assert_equal 0, payload["summary"]["hackable"]
    assert_equal 1, payload["summary"]["decision_unknown"]
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
    assert_includes text, "blocked at the edge"
    assert_includes text, "UNKNOWN"
    refute_includes text, "WHAT THIS MEANS"
  end

  def test_text_exposed_shows_a_plain_answer_and_fix
    text = render(vulnerable_result, "text")
    assert_includes text, "YES — this host can be hacked by PHP2Shell"
    assert_includes text, "HACKABLE"
    assert_includes text, "Upgrade PHP to 8.2.35 or later."
    refute_includes text, "TECHNICAL DETAILS"
  end

  def test_text_verbose_adds_the_technical_detail
    text = render(vulnerable_result, "text", verbose: true)
    assert_includes text, "TECHNICAL DETAILS"
    assert_includes text, "TECHNICAL SIGNALS"
    assert_includes text, "HOW TO FIX IT"
    assert_includes text, "MITRE ATT&CK"
  end

  def test_exposed_targets_get_handoff_actions
    labels = vulnerable_result.next_actions.map(&:label)
    assert_includes labels, "Emit a CI-ready SARIF report"
    assert_includes labels, "Inventory sibling hosts (authorized)"
  end

  def test_blocked_targets_offer_a_browser_ua_retry
    labels = blocked_result.next_actions.map(&:label)
    assert_includes labels, "Retry with a browser-compatible User-Agent (authorized)"
  end

  def test_browser_ua_retry_is_not_suggested_when_already_enabled
    result = scan_with(browser_ua: true) do |uri, purpose, _requests|
      probe(uri, status: 403, body: "<html><title>Blocked</title></html>", purpose: purpose)
    end
    labels = result.next_actions.map(&:label)
    refute_includes labels, "Retry with a browser-compatible User-Agent (authorized)"
  end

  def test_text_verbose_expands_blocked_detail
    text = render(blocked_result, "text", verbose: true)
    assert_includes text, "Assessment detail:"
    assert_includes text, "TECHNICAL SIGNALS"
    assert_includes text, "PAGES CHECKED"
  end

  def test_chinese_scan_reason_is_localized_at_generation
    result = chinese_blocked_result
    assert_includes result.verdict.reason, "暴露情况尚未验证"
    assert_includes result.verdict.reason, "边缘"
  end

  def test_text_report_renders_chinese_labels
    text = render(chinese_blocked_result, "text", locale: "zh")
    assert_includes text, "结果概览"
    assert_includes text, "图例"
    assert_includes text, "未知"
    assert_includes text, "请勿将其视为安全"
    assert_includes text, "后续步骤"
    assert_includes text, "原因："
    assert_includes text, "提示："
    assert_includes text, "（被拦截 1）"
    refute_includes text, "(被拦截 1)"
    refute_match(/^\s+。$/, text)
    refute_includes text, "FINDINGS"
    refute_includes text, "Bottom line"
  end

  def test_chinese_text_keeps_columns_within_terminal_width
    with_columns(80) do
      text = render(chinese_blocked_result, "text", locale: "zh")
      text.each_line do |line|
        assert_operator PHP2ShellPOC2026::Layout.display_width(line.chomp), :<=, 80, line
      end
    end
  end

  def test_text_report_stays_english_by_default
    text = render(chinese_blocked_result, "text")
    assert_includes text, "FINDINGS"
    assert_includes text, "Bottom line"
    refute_includes text, "结果概览"
  end

  def test_machine_formats_do_not_use_text_translations
    payload = JSON.parse(render(chinese_blocked_result, "json", locale: "zh"))
    result = payload["results"].values.first
    assert_equal "3.0", payload["schema_version"]
    assert_equal "inconclusive", result["verdict"]["status"]
    assert_equal "INCONCLUSIVE", result["verdict"]["label"]
    refute_includes JSON.generate(payload), "结果概览"
  end

  def test_decision_card_answers_yes_for_exposed_host
    text = render(vulnerable_result, "text")
    assert_includes text, "DECISION"
    assert_includes text, "YES — this host can be hacked by PHP2Shell"
    assert_includes text, "ACTION"
    assert_includes text, "A remote attacker could exploit this host without logging in."
    assert_includes text, "upgrade PHP now"
  end

  def test_decision_card_answers_no_for_patched_host
    text = render(patched_result, "text")
    assert_includes text, "NO — no PHP2Shell exposure was found"
    assert_includes text, "no action needed on the pages tested"
  end

  def test_decision_card_answers_unknown_for_blocked_host
    text = render(blocked_result, "text")
    assert_includes text, "UNKNOWN — the scanner could not tell"
    assert_includes text, "could not see enough of the host"
    assert_includes text, "check the PHP version"
  end

  def test_decision_card_caveats_version_leaked_on_a_blocked_response
    result = scan_with do |uri, purpose, _requests|
      probe(uri, status: 403, headers: { "x-powered-by" => "PHP/8.2.1" },
                 body: "<html><title>Blocked</title></html>", purpose: purpose)
    end
    text = render(result, "text")
    assert_includes text, "DECISION"
    assert_includes text, "Caveat: the version came from a blocked response"
  end

  def test_text_report_names_the_edge_block_page
    text = render(ovhcloud_blocked_result, "text")
    assert_includes text, "OVHcloud"
    assert_includes text, "Blocked by OVHcloud"
    assert_includes text, "Retry with a browser-compatible User-Agent"
    verbose = render(ovhcloud_blocked_result, "text", verbose: true)
    assert_includes verbose, "Block page"
  end

  def test_blocked_surface_says_not_observed_instead_of_no
    text = render(blocked_result, "text", verbose: true)
    assert_includes text, "PHP not observed"
    refute_includes text, "PHP no ·"
  end

  def test_decision_comes_before_the_technical_table
    text = render(vulnerable_result, "text", verbose: true)
    assert_operator text.index("DECISION"), :<, text.index("TECHNICAL DETAILS")
  end

  def test_bottom_line_answers_the_hackability_question_directly
    assert_includes render(vulnerable_result, "text"), "YES — 1 target hackable via PHP2Shell"
    assert_includes render(patched_result, "text"), "NO — no target hackable on the pages tested."
    assert_includes render(blocked_result, "text"), "UNKNOWN — the scanner could not check"
  end

  def test_bottom_line_separates_hackable_from_unassessed_targets
    text = PHP2ShellPOC2026::Report.render(
      [vulnerable_result, blocked_result],
      options(format: "text", quiet: true),
      meta: { generated_at: "2026-10-24T00:00:00Z", profile: "standard" }
    )
    flat = text.gsub(/\s+/, " ")
    assert_includes flat, "YES — 1 target hackable via PHP2Shell"
    assert_includes flat, "1 other target could not be assessed"
    refute_includes flat, "NO — no target hackable"
  end

  def test_json_carries_answer_and_action
    payload = JSON.parse(render(vulnerable_result, "json"))
    assert_equal 1, payload["summary"]["hackable"]
    assert_equal 0, payload["summary"]["decision_unknown"]
    hackability = payload["results"].values.first["hackability"]
    assert_equal "yes", hackability["answer"]
    assert_includes hackability["action"], "upgrade PHP"

    blocked = JSON.parse(render(blocked_result, "json"))
    hackability = blocked["results"].values.first["hackability"]
    assert_equal "unknown", hackability["answer"]
    refute_nil hackability["action"]
  end

  def test_markdown_carries_the_decision_line
    assert_includes render(vulnerable_result, "markdown"), "YES — hackable via PHP2Shell"
    assert_includes render(blocked_result, "markdown"), "UNKNOWN — cannot be determined"
  end

  def test_markdown_summary_has_a_hackable_column
    text = render(vulnerable_result, "markdown")
    assert_includes text, "| Hackable? |"
    assert_includes text, "| YES |"
  end

  def test_csv_carries_the_decision_columns
    lines = render(vulnerable_result, "csv").lines
    assert_includes lines.first, "hackable,answer,decision_action"
    assert_includes lines.last, "true,yes,"
    assert_includes lines.last, "upgrade PHP"
  end

  def test_sarif_carries_the_decision
    payload = JSON.parse(render(blocked_result, "sarif"))
    result = payload["runs"].first["results"].first
    assert_nil result["properties"]["hackable"]
    assert_equal "unknown", result["properties"]["answer"]
    assert_includes result["message"]["text"], "decision UNKNOWN"
  end

  def test_chinese_decision_card_is_localized
    text = render(chinese_blocked_result, "text", locale: "zh")
    assert_includes text, "决策"
    assert_includes text, "行动"
    assert_includes text, "未知"
  end
end
