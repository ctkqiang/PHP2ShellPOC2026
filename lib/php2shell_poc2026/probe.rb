# frozen_string_literal: true

require "digest"
require "time"
require_relative "sanitize"

module PHP2ShellPOC2026
  # One HTTP response, kept whole — headers, status and (capped) body —
  # because every later judgement is a reading of the same evidence. Holding
  # the response means the scanner never re-fetches a URL to answer a
  # follow-up question, and re-fetching is both slower and noisier.
  class Probe
    PHP_VERSION_IN_HEADER = %r{PHP/(\d+\.\d+(?:\.\d+)?)}i
    PHP_VERSION_ANY       = /\b(\d+\.\d+(?:\.\d+)?)\b/

    TEXTUAL_TYPES = %r{\A(?:text/|application/(?:xhtml\+xml|xml|json|javascript|ecmascript))}i

    attr_reader :uri, :method, :purpose, :status, :headers, :set_cookies, :body,
                :elapsed_ms, :redirects, :cert, :error, :error_kind, :truncated,
                :http_version, :request_uri

    def initialize(uri:, status: nil, headers: {}, set_cookies: [], body: "",
                   elapsed_ms: 0, redirects: [], cert: nil, error: nil,
                   error_kind: nil, truncated: false, http_version: nil,
                   method: "GET", purpose: nil, request_uri: nil)
      @uri          = uri
      @method       = method
      @purpose      = purpose
      @status       = status
      @headers      = headers || {}
      @set_cookies  = Array(set_cookies)
      @body         = body.to_s
      @elapsed_ms   = elapsed_ms.to_f
      @redirects    = Array(redirects)
      @cert         = cert
      @error        = error
      @error_kind   = error_kind
      @truncated    = truncated
      @http_version = http_version
      @request_uri  = request_uri || (uri && uri.request_uri)
      @text_body    = nil
    end

    def url
      uri && uri.to_s
    end

    def header(name)
      headers[name.to_s.downcase]
    end

    def server
      header("server")
    end

    def x_powered_by
      header("x-powered-by")
    end

    def content_type
      header("content-type")
    end

    def charset
      value = content_type.to_s
      value[/charset\s*=\s*"?([^";\s]+)"?/i, 1]
    end

    def textual?
      type = content_type.to_s
      type.empty? || type.match?(TEXTUAL_TYPES)
    end

    def text_body
      @text_body ||= if textual?
                       Sanitize.decode_body(body, charset)
                     else
                       Sanitize.utf8(body)
                     end
    end

    def body_sha256
      @body_sha256 ||= Digest::SHA256.hexdigest(body)
    end

    def body_length
      body.bytesize
    end

    def title
      return @title if defined?(@title)

      @title = if textual?
                 raw = text_body[/<title[^>]*>(.*?)<\/title>/im, 1]
                 raw ? Sanitize.terminal(raw.gsub(/<[^>]+>/, " "), max: 160) : nil
               end
    end

    def generator
      return @generator if defined?(@generator)

      raw = text_body[/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i, 1]
      @generator = raw && Sanitize.terminal(raw, max: 120)
    end

    def error?
      !error.nil?
    end

    def ok?
      !error? && status.to_i.between?(200, 299)
    end

    def redirect?
      !error? && status.to_i.between?(300, 399) && !header("location").to_s.empty?
    end

    def denied?
      !error? && [401, 403, 406, 451].include?(status.to_i)
    end

    def not_found?
      !error? && [404, 410].include?(status.to_i)
    end

    def rate_limited?
      !error? && status.to_i == 429
    end

    def server_error?
      !error? && status.to_i.between?(500, 599)
    end

    def usable?
      !error? && status.to_i.between?(200, 399)
    end

    def status_class
      return :error if error?
      return :denied if denied?
      return :rate_limited if rate_limited?
      return :not_found if not_found?
      return :server_error if server_error?
      return :redirect if redirect?
      return :ok if ok?

      :other
    end

    # -- PHP evidence -----------------------------------------------------

    def php_version_from_headers
      headers.each do |name, value|
        text = value.to_s
        if (match = text.match(PHP_VERSION_IN_HEADER))
          return [match[1], "#{name} header"]
        end
        next unless name.to_s.match?(/php/i) && !text.match?(/PHP\//i)

        if (match = text.match(PHP_VERSION_ANY))
          return [match[1], "#{name} header"]
        end
      end
      nil
    end

    def phpinfo?
      return false unless textual?

      text = text_body
      return true if text.match?(/<title[^>]*>[^<]*phpinfo\(\)/i)
      return true if text.match?(/phpinfo\(\)/i) && text.match?(/PHP Version/i)
      return true if text.match?(/PHP Logo/i) && text.match?(/PHP Version/i)

      false
    end

    def php_version_from_phpinfo
      return nil unless phpinfo?

      text = text_body
      patterns = [
        /PHP Version\s*(?:<\/?[^>]+>\s*)*(\d+\.\d+(?:\.\d+)?)/i,
        /<title[^>]*>[^<]*PHP\s+(\d+\.\d+(?:\.\d+)?)/i,
        /PHP\s+(\d+\.\d+(?:\.\d+)?)\s*-\s*phpinfo\(\)/i
      ]
      patterns.each do |pattern|
        match = text.match(pattern)
        return [match[1], "phpinfo() page"] if match
      end
      nil
    end

    def php_version
      php_version_from_headers || php_version_from_phpinfo
    end

    def php_cookie?
      set_cookies.any? { |cookie| cookie.to_s.match?(/(?:\A|;\s*)PHPSESSID=/i) }
    end

    def php_error_page?
      return false unless textual?

      text = text_body
      text.match?(/\bPHP (?:Fatal error|Parse error|Warning|Notice|Deprecated)\b/i) ||
        (text.match?(/Stack trace:/) && text.match?(/#0\s/))
    end

    # Distinctive bodies from PHP-FPM/CGI when a .php path does not map to a
    # script. A 404 with one of these is *positive* evidence that PHP is
    # executing, which is exactly the kind of signal a status-code-only
    # scanner misses.
    def php_fpm_not_found?
      return false unless textual?

      text = text_body.strip
      text.match?(/\A(?:<[^>]+>\s*)*File not found\.?\s*(?:<\/[^>]+>\s*)*\z/i) ||
        text.match?(/\ANo input file specified\.?\z/i) ||
        text.match?(/\AAccess denied\.?\z/i) ||
        text.match?(/\APrimary script unknown\.?\z/i)
    end

    def php_markers
      markers = []
      if (version = php_version_from_headers)
        markers << { kind: "version_header", evidence: "#{version[1]}: PHP/#{version[0]}",
                     confidence: "high" }
      end
      if (version = php_version_from_phpinfo)
        markers << { kind: "phpinfo", evidence: "phpinfo() reports PHP #{version[0]}",
                     confidence: "high" }
      end
      if php_cookie?
        markers << { kind: "session_cookie", evidence: "PHPSESSID cookie issued",
                     confidence: "high" }
      end
      if php_error_page?
        markers << { kind: "error_page", evidence: "PHP error text in response body",
                     confidence: "medium" }
      end
      if php_fpm_not_found?
        markers << { kind: "fpm_not_found", evidence: "PHP-FPM/CGI 'file not found' body",
                     confidence: "high" }
      end
      markers
    end

    # How similar two responses are, 0.0..1.0. Used to distinguish a real
    # path from a catch-all/soft-404, which is the difference between
    # "index.php exists" and "this site returns 200 for everything".
    def similarity_to(other)
      return 0.0 if other.nil?
      return 1.0 if body_sha256 == other.body_sha256 && status == other.status

      score = 0.0
      score += 0.45 if status == other.status
      score += 0.25 if title && other.title && title == other.title
      score += 0.20 if body_length.positive? && other.body_length.positive? &&
                       (length_ratio(other) >= 0.85)
      score += 0.10 if content_type == other.content_type
      score.clamp(0.0, 1.0).round(2)
    end

    def length_ratio(other)
      return 0.0 if body_length.zero? || other.body_length.zero?

      [body_length, other.body_length].min.to_f / [body_length, other.body_length].max
    end

    def cert_summary
      return nil unless cert

      subject = cert.subject.to_a.find { |name, _, _| name == "CN" }
      issuer  = cert.issuer.to_a.find { |name, _, _| name == "CN" }
      san     = cert.extensions.find { |ext| ext.oid == "subjectAltName" }
      san_names = san ? san.value.split(",").map(&:strip).reject(&:empty?) : []

      {
        subject: subject && subject[1],
        issuer: issuer && issuer[1],
        san: san_names,
        not_before: cert.not_before.utc.iso8601,
        not_after: cert.not_after.utc.iso8601,
        serial: cert.serial.to_s(16).upcase
      }
    rescue StandardError
      nil
    end

    def to_h(include_body: false)
      hash = {
        method: method,
        purpose: purpose,
        url: Sanitize.url(url),
        request_uri: Sanitize.url(request_uri),
        status: status,
        status_class: status_class,
        elapsed_ms: elapsed_ms.round(1),
        bytes: body_length,
        body_sha256: body_sha256,
        truncated: truncated,
        http_version: http_version,
        title: title,
        server: server && Sanitize.header(server),
        x_powered_by: x_powered_by && Sanitize.header(x_powered_by),
        content_type: content_type && Sanitize.header(content_type),
        set_cookie_names: set_cookies.map { |c| cookie_name(c) }.reject(&:empty?).uniq,
        redirects: redirects.map { |r| r.transform_values { |v| Sanitize.url(v) } },
        error: error && Sanitize.terminal(error),
        error_kind: error_kind,
        tls: cert_summary,
        php_markers: php_markers
      }
      hash[:body_excerpt] = Sanitize.excerpt(text_body, max: 512) if include_body && textual?
      hash
    end

    private

    def cookie_name(cookie)
      Sanitize.terminal(cookie.to_s.split(";", 2).first.to_s.split("=", 2).first.to_s, max: 80)
    end
  end
end
