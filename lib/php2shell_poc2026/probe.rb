# frozen_string_literal: true

module PHP2ShellPOC2026
  # One HTTP response, kept whole — headers, status and body — because every
  # later judgement (is this PHP, which version, how exposed) is a reading of
  # the same evidence. Holding the response means the scanner never has to
  # re-fetch a URL to answer a follow-up question, and re-fetching is both
  # slower and noisier than remembering.
  class Probe
    attr_reader :uri, :headers, :status, :body

    def initialize(uri, headers, status, body)
      @uri     = uri
      @headers = headers
      @status  = status
      @body    = body
    end

    # The strongest passive signal we have: a server that volunteers its PHP
    # version in a response header has already answered the question the
    # whole tool exists to ask.
    def php_powered_by
      headers["x-powered-by"].to_s[/PHP\/(\d+\.\d+(?:\.\d+)?)/i, 1]
    end

    # PHPSESSID tells us the session upload-progress machinery (the
    # CVE-2026-109619 arm) is live on this endpoint, which is the difference
    # between "the interpreter is old" and "this specific path is reachable".
    def session_cookie?
      Array(headers["set-cookie"]).any? { |c| c.match?(/PHPSESSID/i) }
    end

    def php_error_page?
      body.match?(/PHP (?:Fatal error|Parse error|Warning)/i)
    end

    # An exposed phpinfo() hands over the version, the SAPI and half the
    # host's configuration in one request. Attackers love it, so we surface
    # it as an attack-surface flag rather than quietly using it for version
    # extraction and moving on.
    def version_from_phpinfo
      return nil unless body.match?(/phpinfo\(\)|PHP Logo|PHP Version/i)

      body[/<title>PHP (?:Version )?(\d+\.\d+(?:\.\d+)?)/i, 1] ||
        body[/PHP Version <\/h1><td class="v">(\d+\.\d+(?:\.\d+)?)/i, 1]
    end

    # Deliberately inclusive: a 302 to a .php script still proves the route
    # exists, and the error-page and cookie checks catch hosts that have
    # stripped X-Powered-By but left everything else talking.
    def php_endpoint?
      return false unless status.between?(200, 399)

      !php_powered_by.nil? || session_cookie? || php_error_page? ||
        !version_from_phpinfo.nil? || uri.path.end_with?(".php")
    end
  end
end
