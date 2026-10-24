# frozen_string_literal: true

require "net/http"
require "openssl"
require "stringio"
require "uri"
require "zlib"
require_relative "errors"
require_relative "probe"
require_relative "rate_limiter"
require_relative "trace"

module PHP2ShellPOC2026
  # The only class that opens a socket. Keeping HTTP mechanics here means
  # the scanner can be tested against a fake transport, and the policy
  # decisions (redirects, retries, rate limits, body caps) live in one place
  # instead of being re-implemented by every caller.
  class HttpClient
    RawResponse = Struct.new(
      :uri, :status, :headers, :set_cookies, :body, :elapsed_ms,
      :truncated, :cert, :http_version,
      keyword_init: true
    )

    REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze
    RETRY_STATUSES    = [429, 502, 503, 504].freeze
    RETRY_ERRORS      = %i[timeout connect protocol].freeze

    DEFAULT_HEADERS = {
      "Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language" => "en-US,en;q=0.7",
      "Accept-Encoding" => "identity",
      "Cache-Control" => "no-cache",
      "Pragma" => "no-cache",
      "Connection" => "close"
    }.freeze

    SENSITIVE_HEADER = /authorization|cookie|token|secret|api[-_]?key/i

    attr_reader :requests

    def initialize(options:, rate_limiter: nil, trace: nil)
      @options      = options
      @rate_limiter = rate_limiter || RateLimiter.new(options.delay_ms)
      @trace        = trace || Trace.new(enabled: options.verbose)
      @requests     = 0
      @proxy        = resolve_proxy
    end

    def exhausted?
      @requests >= @options.max_requests
    end

    def get(uri, follow_redirects: true, purpose: nil)
      redirects = []
      current   = uri
      seen      = { uri.to_s => true }

      loop do
        if exhausted?
          return error_probe(current, "per-target request budget exhausted", :budget, purpose, redirects)
        end

        raw = perform_with_retries(current, include_sensitive: same_origin?(uri, current))
        if follow_redirects && REDIRECT_STATUSES.include?(raw.status.to_i)
          location = raw.headers["location"].to_s
          if location.empty?
            return build_probe(raw, redirects, purpose)
          end

          begin
            next_uri = URI.join(current.to_s, location)
          rescue URI::InvalidURIError => e
            return error_probe(current, "invalid redirect location: #{e.message}", :redirect, purpose, redirects)
          end

          unless next_uri.is_a?(URI::HTTP)
            return error_probe(current, "redirect to non-http(s) scheme rejected: #{next_uri.scheme}",
                               :redirect, purpose, redirects)
          end

          if seen[next_uri.to_s] || redirects.length >= @options.max_redirects
            return error_probe(current, "redirect loop or too many redirects", :redirect, purpose, redirects)
          end

          seen[next_uri.to_s] = true
          redirects << { status: raw.status.to_i, from: current.to_s, to: next_uri.to_s }
          @trace.add("--> #{raw.status} redirect to #{next_uri}")
          current = next_uri
          next
        end

        return build_probe(raw, redirects, purpose)
      end
    rescue NetworkError => e
      @trace.add("xxx #{current}: #{e.kind}: #{e.message}")
      error_probe(current, e.message, e.kind, purpose, redirects)
    end

    private

    def same_origin?(a, b)
      a.scheme == b.scheme && a.host.to_s.downcase == b.host.to_s.downcase && a.port == b.port
    end

    def perform_with_retries(uri, include_sensitive:)
      attempt = 0
      loop do
        @rate_limiter.wait(uri.host)
        count_request!(uri)

        begin
          raw = fetch_once(uri, include_sensitive: include_sensitive)
          if RETRY_STATUSES.include?(raw.status.to_i) && attempt < @options.retries
            delay = retry_delay(raw, attempt)
            @trace.add("... #{raw.status} retry in #{format('%.1f', delay)}s")
            sleep(delay)
            attempt += 1
            next
          end
          return raw
        rescue NetworkError => e
          if RETRY_ERRORS.include?(e.kind) && attempt < @options.retries
            delay = backoff(attempt)
            @trace.add("... #{e.kind} retry in #{format('%.1f', delay)}s")
            sleep(delay)
            attempt += 1
            next
          end
          raise
        end
      end
    end

    def count_request!(uri)
      @requests += 1
      raise BudgetExceeded.new(uri) if @requests > @options.max_requests
    end

    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
    def fetch_once(uri, include_sensitive:)
      started = monotonic
      host    = unbracket(uri.host)
      http    = http_class(host).new(host, uri.port)

      if uri.scheme == "https"
        http.use_ssl      = true
        http.verify_mode  = @options.verify_tls ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        http.verify_hostname = @options.verify_tls
        http.ca_file      = @options.ca_file if @options.ca_file
      end

      http.open_timeout  = @options.connect_timeout
      http.read_timeout  = @options.timeout
      http.write_timeout = @options.timeout if http.respond_to?(:write_timeout=)

      @trace.add("GET  #{uri}")

      raw = http.start do |conn|
        request = build_request(uri, include_sensitive: include_sensitive)
        result = nil
        conn.request(request) do |response|
          body, truncated = read_body(response)
          body, decoded_truncated = decode_body_encoding(body, response)
          truncated ||= decoded_truncated

          result = RawResponse.new(
            uri: uri,
            status: response.code.to_i,
            headers: response_headers(response),
            set_cookies: response.get_fields("set-cookie") || [],
            body: body,
            elapsed_ms: (monotonic - started) * 1000.0,
            truncated: truncated,
            cert: peer_cert(conn),
            http_version: response.http_version
          )
        end
        result
      end

      @trace.add("<-- #{raw.status} server=#{raw.headers['server'] || 'n/a'} " \
                 "powered-by=#{raw.headers['x-powered-by'] || 'n/a'} " \
                 "bytes=#{raw.body.bytesize} time=#{format('%.0f', raw.elapsed_ms)}ms")
      raw
    rescue NetworkError
      raise
    rescue OpenSSL::SSL::SSLError, Net::OpenTimeout, Net::ReadTimeout, Timeout::Error,
           Net::HTTPBadResponse, EOFError, IOError,
           Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
           Errno::ECONNRESET, Errno::EPIPE, Errno::ETIMEDOUT, Errno::EADDRNOTAVAIL,
           SocketError, URI::InvalidURIError => e
      raise NetworkError.from_exception(e, uri: uri)
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

    def build_request(uri, include_sensitive:)
      request = Net::HTTP::Get.new(uri.request_uri)
      headers = merged_headers

      headers.each do |name, value|
        next if !include_sensitive && name.to_s.match?(SENSITIVE_HEADER)

        request[name] = safe_header(value)
      end

      if include_sensitive
        request["Cookie"] = safe_header(@options.cookie) if @options.cookie
        request["Authorization"] = "Bearer #{@options.bearer}" if @options.bearer
        if @options.basic_auth
          user, pass = @options.basic_auth.split(":", 2)
          request.basic_auth(user, pass.to_s)
        end
      end

      request
    end

    # Header names are case-insensitive. Merge on the downcased name so a
    # user-supplied `user-agent` actually replaces the default instead of
    # being sent alongside it.
    def merged_headers
      merged = {}
      (DEFAULT_HEADERS.merge("User-Agent" => @options.user_agent)).each do |name, value|
        merged[name.downcase] = [name, value]
      end
      @options.headers.each do |name, value|
        merged[name.to_s.downcase] = [name.to_s, value]
      end
      merged.each_value.to_a
    end

    def safe_header(value)
      value.to_s.gsub(/[\r\n]/, " ")
    end

    def read_body(response)
      body = +"".b
      truncated = false
      response.read_body do |chunk|
        remaining = @options.max_body - body.bytesize
        if chunk.bytesize > remaining
          body << chunk.byteslice(0, remaining) if remaining.positive?
          truncated = true
          break
        end
        body << chunk
      end
      [body, truncated]
    end

    # Net::HTTP does not decompress for us. We ask for identity, but some
    # origins ignore that; handle gzip/deflate so a compressed phpinfo page
    # does not read as "no PHP".
    def decode_body_encoding(body, response)
      encoding = response["content-encoding"].to_s.downcase
      return [body, false] if encoding.empty? || encoding == "identity"

      decoded = case encoding
                when "gzip", "x-gzip"
                  Zlib::GzipReader.new(StringIO.new(body)).read(@options.max_body)
                when "deflate"
                  inflate(body)
                else
                  return [body, false]
                end
      truncated = decoded.bytesize >= @options.max_body
      [decoded.byteslice(0, @options.max_body), truncated]
    rescue Zlib::Error
      [body, false]
    end

    def inflate(body)
      Zlib::Inflate.inflate(body)
    rescue Zlib::DataError
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(body)
    end

    def response_headers(response)
      headers = {}
      response.each_header { |name, value| headers[name.downcase] = value }
      headers
    end

    def peer_cert(connection)
      connection.peer_cert
    rescue StandardError
      nil
    end

    def build_probe(raw, redirects, purpose)
      Probe.new(
        uri: raw.uri,
        status: raw.status,
        headers: raw.headers,
        set_cookies: raw.set_cookies,
        body: raw.body,
        elapsed_ms: raw.elapsed_ms,
        redirects: redirects,
        cert: raw.cert,
        truncated: raw.truncated,
        http_version: raw.http_version,
        purpose: purpose
      )
    end

    def error_probe(uri, message, kind, purpose, redirects)
      @trace.add("xxx #{uri}: #{kind}: #{message}")
      Probe.new(uri: uri, status: nil, error: message, error_kind: kind,
                purpose: purpose, redirects: redirects)
    end

    def retry_delay(raw, attempt)
      return backoff(attempt) unless @options.retry_after

      value = raw.headers["retry-after"].to_s
      return backoff(attempt) if value.empty?

      seconds = if value.match?(/\A\d+\z/)
                  value.to_i
                else
                  (Time.httpdate(value) - Time.now).ceil
                end
      seconds.clamp(0, 30)
    rescue ArgumentError
      backoff(attempt)
    end

    def backoff(attempt)
      [0.5 * (2**attempt), 5.0].min
    end

    def resolve_proxy
      return nil if @options.no_proxy

      raw = @options.proxy
      raw ||= ENV["HTTPS_PROXY"] || ENV["https_proxy"] if raw.nil?
      raw ||= ENV["HTTP_PROXY"] || ENV["http_proxy"] if raw.nil?
      raw ||= ENV["ALL_PROXY"] || ENV["all_proxy"] if raw.nil?
      return nil if raw.nil? || raw.to_s.strip.empty?

      uri = URI.parse(raw)
      return nil unless uri.is_a?(URI::HTTP) && uri.host

      {
        host: uri.host,
        port: uri.port || 8080,
        user: uri.user && URI.decode_www_form_component(uri.user),
        pass: uri.password && URI.decode_www_form_component(uri.password)
      }
    rescue URI::InvalidURIError
      nil
    end

    def http_class(host)
      return Net::HTTP unless @proxy
      return Net::HTTP if no_proxy_match?(host)

      Net::HTTP::Proxy(@proxy[:host], @proxy[:port], @proxy[:user], @proxy[:pass])
    end

    # NO_PROXY is honoured for both explicit and environment proxies. A
    # scanner that ignores it will happily send internal traffic through a
    # public proxy, which is exactly the mistake this guard prevents.
    def no_proxy_match?(host)
      return false if @options.proxy # an explicit --proxy wins over NO_PROXY

      entries = (ENV["NO_PROXY"] || ENV["no_proxy"]).to_s.split(",").map(&:strip).reject(&:empty?)
      candidate = host.to_s.downcase.sub(/\A\./, "")

      entries.any? do |entry|
        value = entry.downcase.sub(/\A\./, "")
        value == "*" || candidate == value || candidate.end_with?(".#{value}")
      end
    end

    def unbracket(host)
      text = host.to_s
      text.start_with?("[") && text.end_with?("]") ? text[1..-2] : text
    end

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
