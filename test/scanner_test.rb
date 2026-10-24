# frozen_string_literal: true

require_relative "test_helper"

class ScannerTest < Minitest::Test
  def blocked_response(uri, purpose)
    probe(uri, status: 403, headers: { "server" => "openresty" },
               body: "<html><title>Your request has been blocked</title></html>", purpose: purpose)
  end

  def test_blanket_403_is_blocked_not_clean
    result = scan_with do |uri, purpose, _requests|
      blocked_response(uri, purpose)
    end

    assert_equal :inconclusive, result.verdict.status
    assert_equal :blocked, result.verdict.reason_code
    assert_equal :blocked, result.verdict.access.state
    assert_equal 3, result.probes.size
    assert_equal 3, result.meta[:requests]
    assert_nil result.risk[:score]
    assert_equal "UNKNOWN", result.risk[:grade]
    assert_equal :inconclusive, result.hackability.rating
    assert_nil result.hackability.ratio
    assert_equal 0, result.fingerprint[:coverage][:usable]
    assert_equal 3, result.fingerprint[:coverage][:attempted]
  end

  def test_root_denied_but_control_404_is_restricted
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 403, headers: { "server" => "nginx" }, body: "forbidden", purpose: purpose)
      else
        probe(uri, status: 404, body: "not found", purpose: purpose)
      end
    end

    assert_equal :restricted, result.verdict.access.state
    assert_equal :inconclusive, result.verdict.status
    assert_equal :restricted, result.verdict.reason_code
    assert_equal 4, result.probes.size
  end

  def test_catch_all_is_soft_404
    result = scan_with do |uri, purpose, _requests|
      probe(uri, status: 200, body: "<html><title>Welcome</title><p>Same page</p></html>",
                 purpose: purpose)
    end

    assert_equal :soft_404, result.verdict.access.state
    assert_equal :inconclusive, result.verdict.status
    assert_equal :soft_404, result.verdict.reason_code
    assert_equal 3, result.probes.size
  end

  def test_login_redirect_is_auth_wall
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 302, headers: { "location" => "/login" }, purpose: purpose)
      else
        probe(uri, status: 404, body: "not found", purpose: purpose)
      end
    end

    assert_equal :auth_wall, result.verdict.access.state
    assert_equal :inconclusive, result.verdict.status
    assert_equal :auth_wall, result.verdict.reason_code
    assert_equal 3, result.probes.size
  end

  def test_429_is_rate_limited
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 429, headers: { "retry-after" => "2" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :rate_limited, result.verdict.access.state
    assert_equal :rate_limited, result.verdict.reason_code
    assert_equal :inconclusive, result.verdict.status
  end

  def test_all_errors_is_unreachable
    result = scan_with do |uri, purpose, _requests|
      probe(uri, status: nil, error: "connection refused", error_kind: :connect, purpose: purpose)
    end

    assert_equal :unreachable, result.verdict.access.state
    assert_equal :unreachable, result.verdict.reason_code
    assert_equal :inconclusive, result.verdict.status
  end

  def test_vulnerable_version_is_exposed
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.1", "server" => "nginx" },
                   body: "<html><title>Home</title></html>", purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :vulnerable, result.verdict.status
    assert_equal "8.2.1", result.verdict.version.to_s
    assert_equal "8.2.35", result.verdict.fix_floor.to_s
    assert_equal 9.8, result.risk[:score]
    assert_equal :exposed, result.hackability.rating
    assert_equal 1.0, result.hackability.ratio
    assert_equal 4, result.probes.size
  end

  def test_patched_version_is_not_exposed
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.4.27" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :patched, result.verdict.status
    assert_equal 0.0, result.risk[:score]
    assert_equal :not_exposed, result.hackability.rating
    refute result.exposed?
  end

  def test_eol_branch_is_exposed
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/7.4.33" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :eol, result.verdict.status
    assert_equal "7.4", result.verdict.branch
    assert_equal 10.0, result.risk[:score]
    assert_equal :exposed, result.hackability.rating
  end

  def test_branch_only_version_is_unverified
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/" || uri.path == "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :unknown, result.verdict.status
    assert_equal :branch_only, result.verdict.reason_code
    assert_equal "8.2.35", result.verdict.fix_floor.to_s
    assert_nil result.risk[:score]
  end

  def test_phpinfo_version_is_read
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 200, body: "<html><title>phpinfo()</title><h1>PHP Version 8.2.1</h1></html>",
                   purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :vulnerable, result.verdict.status
    assert_equal "phpinfo() page", result.verdict.version_source
  end

  def test_fpm_file_not_found_is_positive_php_evidence
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 200, body: "<html><title>Static</title></html>", purpose: purpose)
      elsif uri.path.end_with?(".php")
        probe(uri, status: 404, body: "File not found.", purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_equal :unknown, result.verdict.status
    assert_equal :no_version, result.verdict.reason_code
    assert result.verdict.attack_surface[:php_detected]
    refute result.verdict.attack_surface[:php_paths_live]
  end

  def test_no_php_when_control_and_paths_are_normal_404s
    result = scan_with do |uri, purpose, _requests|
      if uri.path == "/"
        probe(uri, status: 200, body: "<html><title>Static</title></html>", purpose: purpose)
      else
        probe(uri, status: 404, body: "not found", purpose: purpose)
      end
    end

    assert_equal :no_php, result.verdict.status
    assert_equal 0.0, result.risk[:score]
    assert_equal :not_exposed, result.hackability.rating
  end

  def test_deep_mode_discovers_sitemap_php_path
    result = scan_with(profile: "deep") do |uri, purpose, _requests|
      case uri.path
      when "/"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.1" }, purpose: purpose)
      when "/robots.txt"
        probe(uri, status: 200, body: "Sitemap: https://192.0.2.10/sitemap.xml\n", purpose: purpose)
      when "/sitemap.xml"
        probe(uri, status: 200, body: "<urlset><url><loc>https://192.0.2.10/real.php</loc></url></urlset>",
                   purpose: purpose)
      when "/real.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.1" }, purpose: purpose)
      when "/index.php"
        probe(uri, status: 200, headers: { "x-powered-by" => "PHP/8.2.1" }, purpose: purpose)
      else
        probe(uri, status: 404, purpose: purpose)
      end
    end

    assert_includes result.fingerprint[:discovered_paths], "/real.php"
    assert(result.probes.any? { |p| p.request_uri == "/real.php" })
    assert_equal :vulnerable, result.verdict.status
  end

  def test_max_requests_caps_deep_scan
    result = scan_with(profile: "deep", max_requests: 4) do |uri, purpose, _requests|
      probe(uri, status: 404, purpose: purpose)
    end

    assert_equal 4, result.meta[:requests]
    assert_equal 4, result.probes.size
  end
end
