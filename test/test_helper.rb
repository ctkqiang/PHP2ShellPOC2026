# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "json"
require "uri"
require "php2shell_poc2026"

ENV["COLUMNS"] ||= "100"

module TestHelpers
  def options(**overrides)
    PHP2ShellPOC2026::Options.new(
      **{
        profile: "standard",
        delay_ms: 0,
        max_requests: 25,
        no_proxy: true,
        no_color: true,
        adaptive: true,
        retries: 0,
        timeout: 2,
        connect_timeout: 1
      }.merge(overrides)
    ).validate!
  end

  def probe(uri, status:, headers: {}, body: "", purpose: nil, error: nil, error_kind: nil)
    path = uri.respond_to?(:request_uri) ? uri.request_uri : uri.to_s
    PHP2ShellPOC2026::Probe.new(
      uri: uri.is_a?(URI) ? uri : URI("https://192.0.2.10#{path}"),
      status: status,
      headers: headers,
      body: body,
      purpose: purpose,
      request_uri: path,
      error: error,
      error_kind: error_kind
    )
  end

  def scan_with(**overrides, &block)
    opts = options(**overrides)
    scanner = PHP2ShellPOC2026::Scanner.new(
      options: opts,
      client_factory: ->(_trace) { FakeClient.new(max_requests: opts.max_requests, &block) }
    )
    scanner.scan("https://192.0.2.10/")
  end

  def target
    PHP2ShellPOC2026::Target.parse("https://192.0.2.10/")
  end

  class FakeClient
    attr_reader :requests

    def initialize(max_requests: 25, &block)
      @block = block
      @requests = 0
      @max_requests = max_requests
    end

    def exhausted?
      @requests >= @max_requests
    end

    def get(uri, follow_redirects: true, purpose: nil)
      @requests += 1
      @block.call(uri, purpose, @requests)
    end
  end
end

class Minitest::Test
  include TestHelpers

  # Locale is process-global by design (the scan and the report must agree).
  # A CLI test that exercises --lang must not leak that choice into the
  # next test's fixtures.
  def teardown
    PHP2ShellPOC2026::I18n.locale = "en"
  end
end
