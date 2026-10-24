# frozen_string_literal: true

require_relative "test_helper"

class VerdictTest < Minitest::Test
  def assess(version, access_state: :open, surface: { php_detected: true })
    access = PHP2ShellPOC2026::Access.new(state: access_state, reason: "test")
    PHP2ShellPOC2026::Verdict.assess(
      version: version,
      version_source: "x-powered-by header",
      precision: version.to_s.split(".").length >= 3 ? :patch : :minor,
      surface: surface,
      access: access
    )
  end

  def test_vulnerable_just_below_floor
    assert_equal :vulnerable, assess("8.2.34").status
    assert_equal :vulnerable, assess("8.3.35").status
    assert_equal :vulnerable, assess("8.4.26").status
    assert_equal :vulnerable, assess("8.5.11").status
  end

  def test_patched_at_or_above_floor
    assert_equal :patched, assess("8.2.35").status
    assert_equal :patched, assess("8.3.36").status
    assert_equal :patched, assess("8.4.27").status
    assert_equal :patched, assess("8.5.12").status
    assert_equal :patched, assess("8.5.99").status
  end

  def test_eol_branches
    assert_equal :eol, assess("7.4.33").status
    assert_equal :eol, assess("8.1.31").status
    assert_equal :eol, assess("5.6.40").status
  end

  def test_branch_only_is_unverified
    verdict = assess("8.2")
    assert_equal :unknown, verdict.status
    assert_equal :branch_only, verdict.reason_code
    assert_equal "8.2.35", verdict.fix_floor.to_s
  end

  def test_newer_than_fix_table_is_unverified
    verdict = assess("8.6.0")
    assert_equal :unknown, verdict.status
    assert_equal :newer_than_table, verdict.reason_code
  end

  def test_no_php_without_markers
    verdict = PHP2ShellPOC2026::Verdict.assess(
      surface: { php_detected: false },
      access: PHP2ShellPOC2026::Access.new(state: :open, reason: "test")
    )
    assert_equal :no_php, verdict.status
  end

  def test_php_without_version_is_unverified
    verdict = PHP2ShellPOC2026::Verdict.assess(
      surface: { php_detected: true },
      access: PHP2ShellPOC2026::Access.new(state: :open, reason: "test")
    )
    assert_equal :unknown, verdict.status
    assert_equal :no_version, verdict.reason_code
  end

  def test_blocked_is_inconclusive
    verdict = assess(nil, access_state: :blocked, surface: { php_detected: false })
    assert_equal :inconclusive, verdict.status
    assert_equal :blocked, verdict.reason_code
  end

  def test_auth_wall_without_version_is_inconclusive
    verdict = assess(nil, access_state: :auth_wall, surface: { php_detected: true })
    assert_equal :inconclusive, verdict.status
    assert_equal :auth_wall, verdict.reason_code
  end

  def test_soft_404_without_version_is_inconclusive
    verdict = assess(nil, access_state: :soft_404, surface: { php_detected: false })
    assert_equal :inconclusive, verdict.status
    assert_equal :soft_404, verdict.reason_code
  end
end
