# frozen_string_literal: true

require_relative "test_helper"
require "socket"
require "zlib"

class HttpClientTest < Minitest::Test
  def http_options(**overrides)
    PHP2ShellPOC2026::Options.new(
      **{
        timeout: 2,
        connect_timeout: 1,
        retries: 0,
        delay_ms: 0,
        max_redirects: 5,
        max_body: 1024,
        no_proxy: true,
        verify_tls: false
      }.merge(overrides)
    ).validate!
  end

  def with_server(*responses)
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    thread = Thread.new do
      responses.each do |response|
        socket = server.accept
        begin
          while (line = socket.gets)
            break if line == "\r\n"
          end
          socket.write(response)
        ensure
          socket.close
        end
      end
    rescue IOError, Errno::EBADF
      # Server closed by the test teardown.
    ensure
      server.close unless server.closed?
    end
    yield port
  ensure
    server&.close unless server&.closed?
    thread&.join(2)
  end

  def response(status: 200, headers: {}, body: "")
    header_lines = {
      "Content-Type" => "text/html; charset=utf-8",
      "Content-Length" => body.bytesize.to_s,
      "Connection" => "close"
    }.merge(headers)
    "HTTP/1.1 #{status} OK\r\n" +
      header_lines.map { |name, value| "#{name}: #{value}\r\n" }.join +
      "\r\n" + body
  end

  def test_reads_status_headers_body_and_php_cookie
    body = "<html><title>Home</title></html>"
    payload = response(
      headers: {
        "X-Powered-By" => "PHP/8.2.1",
        "Set-Cookie" => "PHPSESSID=abc; path=/",
        "Server" => "nginx"
      },
      body: body
    )

    with_server(payload) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options)
      probe = client.get(URI("http://127.0.0.1:#{port}/"))
      assert_equal 200, probe.status
      assert_equal body, probe.body
      assert_equal "nginx", probe.server
      assert_equal "PHP/8.2.1", probe.x_powered_by
      assert_equal ["8.2.1", "x-powered-by header"], probe.php_version_from_headers
      assert probe.php_cookie?
      assert_equal 1, client.requests
    end
  end

  def test_denied_response
    with_server(response(status: 403, body: "blocked")) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options)
      probe = client.get(URI("http://127.0.0.1:#{port}/"))
      assert probe.denied?
      assert_equal 403, probe.status
    end
  end

  def test_follows_redirects
    first = response(status: 302, headers: { "Location" => "/next" }, body: "")
    second = response(body: "arrived")

    with_server(first, second) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options)
      probe = client.get(URI("http://127.0.0.1:#{port}/start"))
      assert_equal 200, probe.status
      assert_equal "arrived", probe.body
      assert_equal 1, probe.redirects.size
      assert_equal "/next", probe.uri.path
      assert_equal 2, client.requests
    end
  end

  def test_body_cap_truncates
    body = "x" * 5000
    with_server(response(body: body)) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options(max_body: 1024))
      probe = client.get(URI("http://127.0.0.1:#{port}/"))
      assert_equal 1024, probe.body.bytesize
      assert probe.truncated
    end
  end

  def test_gzip_is_decoded
    body = "compressed php"
    gzipped = Zlib.gzip(body)
    with_server(response(headers: { "Content-Encoding" => "gzip" }, body: gzipped)) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options)
      probe = client.get(URI("http://127.0.0.1:#{port}/"))
      assert_equal body, probe.body
    end
  end

  def test_budget_is_reported_as_exhausted
    with_server(response(body: "one")) do |port|
      client = PHP2ShellPOC2026::HttpClient.new(options: http_options(max_requests: 1))
      first = client.get(URI("http://127.0.0.1:#{port}/"))
      assert_equal 200, first.status
      assert client.exhausted?
      second = client.get(URI("http://127.0.0.1:#{port}/"))
      assert_equal :budget, second.error_kind
      assert_equal 1, client.requests
    end
  end
end
