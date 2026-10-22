# frozen_string_literal: true

require "net/http"
require "uri"
require "openssl"

module PHP2ShellPOC2026
  # Orchestrates one scan: fetch, fingerprint, classify, weight, enrich —
  # then hands back a single ScanResult that knows how to render itself.
  #
  # The scanner only ever issues ordinary GET requests. There is no payload
  # anywhere in this file, on purpose: triage tools get run against hosts
  # the operator has permission to touch, and a passive-by-construction tool
  # can be pointed at a wider set of them than an exploitative one.
  class Scanner
    MAX_REDIRECTS = 5

    # Deep mode's candidate paths. They are generic rather than
    # WordPress-specific so the tool stays useful against non-WP estates;
    # index.php is included because it is the cheapest proof that PHP is
    # actually executing rather than merely being proxied.
    DEEP_PROBE_PATHS = %w[
      /index.php
      /phpinfo.php
      /info.php
      /test.php
      /i.php
      /php.php
    ].freeze

    # The complete answer for one target. It is a struct rather than a hash
    # so that a typo in a key is a NoMethodError at development time instead
    # of a silently empty field in someone's report, and so the CLI, the
    # JSON emitter and any future test all read the same shape.
    ScanResult = Struct.new(
      :target, :verdict, :environment, :risk,
      :attack_chain, :detections, :red_team, :tooling,
      :fingerprint, :hackability, :remediation, :trace,
      keyword_init: true
    ) do
      def exposed?
        verdict.exposed?
      end

      def to_h
        {
          verdict:      verdict.to_h,
          environment:  environment.to_h,
          risk:         risk,
          attack_chain: attack_chain.map(&:to_h),
          detections:   detections.map(&:to_h),
          red_team:     red_team,
          tooling:      tooling.map(&:to_h),
          fingerprint:  fingerprint,
          hackability:  hackability.to_h,
          remediation:  remediation,
          trace:        trace
        }
      end
    end

    def initialize(timeout: 10, verify_tls: true, deep: false, verbose: false)
      @timeout    = timeout
      @verify_tls = verify_tls
      @deep       = deep
      @verbose    = verbose
      @trace      = []
    end

    def scan(target)
      @trace = []
      root   = normalize(target)

      probes = [fetch(root)]
      probes.concat(deep_probes(root)) if @deep

      live          = probes.compact
      version, source = extract_version(live)
      verdict       = Verdict.assess(version, surface_of(live), source)
      env           = Environment.new(live.first)

      trace("probes: #{live.size}/#{probes.size} usable, version #{version || 'unknown'}" \
            "#{source ? " (#{source})" : ''}, verdict #{verdict.status}")

      ScanResult.new(
        target:       target,
        verdict:      verdict,
        environment:  env,
        risk:         Risk.assess(verdict, env),
        attack_chain: Attack.techniques_for(verdict),
        detections:   Detections.for(verdict, env),
        red_team:     RedTeam.notes(verdict, env),
        tooling:      Tooling.catalogue(verdict, env),
        fingerprint:  fingerprint_of(live),
        hackability:  Hackability.assess(verdict, env),
        remediation:  Remediation.for(verdict, env),
        trace:        @trace
      )
    end

    private

    def deep_probes(root)
      DEEP_PROBE_PATHS.map { |path| fetch(at_path(root, path)) }
    end

    def normalize(target)
      uri = URI.parse(target.include?("://") ? target : "https://#{target}")
      raise URI::InvalidURIError, "not an http(s) URL: #{target}" unless uri.is_a?(URI::HTTP)

      uri.path = "/" if uri.path.empty?
      uri
    end

    def at_path(uri, path)
      uri.dup.tap { |u| u.path = path }
    end

    # One GET, following redirects a bounded number of times. A failed probe
    # is a nil rather than an exception because a single unreachable path
    # should degrade the verdict to :unknown, not abort a scan of a host we
    # can otherwise reach.
    def fetch(uri, redirects_left = MAX_REDIRECTS)
      raise "too many redirects for #{uri}" if redirects_left.negative?

      trace("GET  #{uri}")
      res = Net::HTTP.start(
        uri.host, uri.port,
        use_ssl:      uri.scheme == "https",
        open_timeout: @timeout,
        read_timeout: @timeout,
        verify_mode:  @verify_tls ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      ) { |http| http.get(uri.request_uri, "User-Agent" => PHP2ShellPOC2026::USER_AGENT) }

      if res.is_a?(Net::HTTPRedirection)
        location = URI.join(uri.to_s, res["location"])
        trace("--> #{res.code} redirect to #{location}")
        return fetch(location, redirects_left - 1)
      end

      headers = res.each_header.to_h
      trace("<-- #{res.code} server=#{headers['server'] || 'n/a'} powered-by=#{headers['x-powered-by'] || 'n/a'}")
      Probe.new(uri, headers, res.code.to_i, res.body.to_s)
    rescue StandardError => e
      warn "  ! #{uri}: #{e.class}: #{e.message}"
      trace("xxx #{uri}: #{e.class}: #{e.message}")
      nil
    end

    # X-Powered-By first because it is exact; a phpinfo page second because
    # it is authoritative but rarer. Nothing is inferred from response times
    # or error-page wording — too many false positives to be worth the noise.
    # The source travels with the number so a report can say *how* it knows,
    # which is the difference between a claim and a finding.
    def extract_version(probes)
      probes.each do |probe|
        if (raw = probe.php_powered_by)
          return [Gem::Version.new(raw), "X-Powered-By header"]
        end
        if (raw = probe.version_from_phpinfo)
          return [Gem::Version.new(raw), "phpinfo() page"]
        end
      end
      [nil, nil]
    end

    # The raw evidence behind the verdict, kept verbatim: what the headers
    # actually said, which cookies were issued, what the probes returned.
    # Printed in the text report and carried in JSON so a reader can
    # re-derive the verdict themselves instead of taking our word for it.
    def fingerprint_of(probes)
      cookies = probes.flat_map { |p| Array(p.headers["set-cookie"]) }
                      .map { |c| c.split(";", 2).first.to_s.split("=", 2).first }
                      .reject(&:empty?)
                      .uniq

      {
        x_powered_by: probes.map { |p| p.headers["x-powered-by"] }.compact.first,
        server:       probes.map { |p| p.headers["server"] }.compact.first,
        cookie_names: cookies,
        statuses:     probes.map(&:status).uniq.sort,
        probed_paths: probes.map { |p| p.uri.path }.uniq
      }
    end

    # These four flags are what the rest of the report hangs its attack
    # surface claims on: is PHP here at all, is the upload-progress path
    # reachable, is phpinfo leaking, are errors verbose. Each maps to a
    # sentence someone can verify by hand.
    def surface_of(probes)
      {
        php_detected:    probes.any?(&:php_endpoint?),
        upload_progress: probes.any?(&:session_cookie?),
        phpinfo_exposed: probes.any? { |p| !p.version_from_phpinfo.nil? },
        php_errors:      probes.any?(&:php_error_page?)
      }
    end

    def trace(line)
      @trace << line if @verbose
    end
  end
end
