# frozen_string_literal: true

require_relative "test_helper"

class BlockPageTest < Minitest::Test
  def denied_probe(headers: {}, body: "<html><title>Blocked</title></html>")
    PHP2ShellPOC2026::Probe.new(
      uri: URI("https://192.0.2.10/"),
      status: 403,
      headers: headers,
      body: body,
      purpose: "root",
      request_uri: "/"
    )
  end

  def test_recognizes_the_ovhcloud_bot_block_page
    probe = denied_probe(
      headers: { "server" => "openresty", "x-ovh-webhosting-id" => "abc123" },
      body: <<~HTML
        <html><head><title>Your request has been blocked - OVHcloud</title></head>
        <body>Your request has been blocked. Request blocked due to suspicious activity.
        Please try again later. OVHcloud.</body></html>
      HTML
    )

    result = PHP2ShellPOC2026::BlockPage.analyze([probe])
    assert_equal "OVHcloud", result.vendor
    assert_includes result.summary, "suspicious activity"
    assert result.ua_sensitive
    assert_equal 403, result.status
  end

  def test_recognizes_cloudflare_from_the_cf_ray_header
    probe = denied_probe(
      headers: { "server" => "cloudflare", "cf-ray" => "abc123" },
      body: "<html><title>Attention Required! | Cloudflare</title></html>"
    )

    result = PHP2ShellPOC2026::BlockPage.analyze([probe])
    assert_equal "Cloudflare", result.vendor
    assert result.ua_sensitive
  end

  def test_generic_denial_does_not_invent_a_vendor
    result = PHP2ShellPOC2026::BlockPage.analyze(
      [denied_probe(body: "<html><title>Request denied by edge policy</title></html>")]
    )
    assert_nil result.vendor
    assert_includes result.summary, "Request denied"
  end

  def test_a_short_meaningless_title_falls_back_to_the_status
    result = PHP2ShellPOC2026::BlockPage.analyze(
      [denied_probe(body: "<html><title>Blocked</title></html>")]
    )
    assert_equal "HTTP 403", result.summary
  end

  def test_ignores_a_usable_response
    probe = PHP2ShellPOC2026::Probe.new(
      uri: URI("https://192.0.2.10/"), status: 200,
      headers: { "content-type" => "text/html" }, body: "<title>Home</title>"
    )
    assert_nil PHP2ShellPOC2026::BlockPage.analyze([probe])
  end
end
