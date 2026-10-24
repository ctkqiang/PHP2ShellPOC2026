# frozen_string_literal: true

require "securerandom"
require "time"

require_relative "access"
require_relative "attack"
require_relative "detections"
require_relative "discovery"
require_relative "dns_info"
require_relative "environment"
require_relative "frameworks"
require_relative "hackability"
require_relative "http_client"
require_relative "i18n"
require_relative "next_actions"
require_relative "rate_limiter"
require_relative "red_team"
require_relative "remediation"
require_relative "risk"
require_relative "scan_result"
require_relative "target"
require_relative "tooling"
require_relative "trace"
require_relative "verdict"

module PHP2ShellPOC2026
  # Orchestrates one scan: fetch, classify access, probe adaptively,
  # fingerprint, weigh, enrich — then hands back a ScanResult.
  #
  # The scanner only ever issues ordinary GET requests. There is no payload
  # anywhere in this file, on purpose: triage tools get run against hosts
  # the operator has permission to touch, and a passive-by-construction tool
  # can be pointed at a wider set of them than an exploitative one.
  #
  # The central methodological change is the control probe. Before trusting
  # a 403 or a 404 as evidence about PHP, the scanner asks for a random path
  # that cannot exist. If that path is also denied, the edge blocked the
  # scanner and the honest answer is "unverified", not "not hackable".
  class Scanner
    STANDARD_PATHS = %w[/index.php].freeze

    DEEP_PATHS = %w[
      /index.php
      /phpinfo.php
      /info.php
      /test.php
      /i.php
      /php.php
      /admin.php
      /login.php
      /api.php
      /health.php
      /status.php
    ].freeze

    FRAMEWORK_VERSION_PATHS = {
      "WordPress" => %w[/readme.html],
      "Drupal"    => %w[/CHANGELOG.txt /core/CHANGELOG.txt],
      "Joomla"    => %w[/administrator/manifests/files/joomla.xml]
    }.freeze

    MAX_DISCOVERED_PATHS = 5

    def initialize(options:, rate_limiter: nil, client_factory: nil)
      @options      = options
      @rate_limiter = rate_limiter || RateLimiter.new(options.delay_ms)
      @client_factory = client_factory || lambda do |trace|
        HttpClient.new(options: @options, rate_limiter: @rate_limiter, trace: trace)
      end
    end

    def scan(raw_target, scope_decision: nil)
      # The generators below (verdict reasons, next actions, detections)
      # bake their prose into the result. Pin the locale for the whole scan
      # so those strings match --lang even if a caller left a different
      # locale set globally.
      I18n.with_locale(@options.locale) do
        perform_scan(raw_target, scope_decision: scope_decision)
      end
    end

    def perform_scan(raw_target, scope_decision: nil)
      started = monotonic
      target  = raw_target.is_a?(Target) ? raw_target : Target.parse(raw_target)
      trace   = Trace.new(enabled: @options.verbose)
      client  = @client_factory.call(trace)
      probes  = []
      discovery = { paths: [], robots: nil, sitemap: nil, disallowed: [] }

      root = client.get(target.uri, follow_redirects: true, purpose: "root")
      probes << root

      controls = fetch_controls(client, target)
      probes.concat(controls)

      access = classify_access(probes, root)
      trace.add("access: #{access.state} — #{access.reason}")

      if proceed_with_main?(access)
        paths = main_paths_for(target, probes)
        fetch_paths(client, target, paths, probes, trace)

        if @options.profile == "deep" && access.state == :open && root.usable?
          discovery = discover_paths(client, target, probes, trace)
          fetch_paths(client, target, discovery[:paths], probes, trace)
        end
      end

      access = classify_access(probes, root)
      content_probes = content_probes(probes)
      frameworks = Frameworks.detect(content_probes)
      surface = surface_of(content_probes, access, frameworks)
      version, source, precision, candidates = extract_version(probes)
      surface[:php_versioned] = !version.nil?

      verdict = Verdict.assess(
        version: version, version_source: source, precision: precision,
        surface: surface, access: access
      )

      tls = probes.map(&:cert_summary).compact.first
      dns = DnsInfo.lookup(target.ascii_host)
      environment = Environment.new(probes, access: access, tls: tls, dns: dns, surface: surface)
      coverage = coverage_of(content_probes)
      risk = Risk.assess(verdict, environment)
      hackability = Hackability.assess(verdict, environment, risk, coverage: coverage)

      trace.add("probes: #{content_probes.size} content, #{client.requests} requests, " \
                "version #{version || 'unknown'}, verdict #{verdict.status}")

      ScanResult.new(
        target: target,
        verdict: verdict,
        environment: environment,
        risk: risk,
        attack_chain: Attack.kill_chain(verdict),
        assessment_path: Attack.assessment_path(
          verdict, environment, requests: client.requests, profile: @options.profile
        ),
        detections: Detections.for(verdict, environment),
        red_team: RedTeam.notes(verdict, environment),
        tooling: Tooling.catalogue(verdict, environment, @options),
        fingerprint: fingerprint_of(
          target, probes, environment, access, coverage, candidates, tls, dns, discovery, client
        ),
        hackability: hackability,
        remediation: Remediation.for(verdict, environment),
        next_actions: NextActions.for(verdict, environment, target, @options),
        probes: probes,
        trace: trace,
        meta: {
          tool_version: VERSION,
          started_at: Time.now.utc.iso8601,
          duration_ms: ((monotonic - started) * 1000.0).round(1),
          requests: client.requests,
          profile: @options.profile,
          scope: scope_decision,
          target: target.to_h,
          max_requests: @options.max_requests,
          adaptive: @options.adaptive
        }
      )
    rescue UsageError
      raise
    rescue StandardError => e
      target ||= raw_target.is_a?(Target) ? raw_target : nil
      raise e unless target

      ScanResult.failed(target, e, @options, trace: trace, meta: { scope: scope_decision })
    end

    private :perform_scan

    # Dry-run plan. No socket is opened; this is the artifact an operator
    # can review against the program's scope and ROE before running anything.
    def plan(raw_target, scope_decision: nil)
      target = raw_target.is_a?(Target) ? raw_target : Target.parse(raw_target)
      token = SecureRandom.hex(8)
      controls = ["/php2shell-#{token}.txt"]
      controls << "/php2shell-#{token}.php" unless @options.profile == "passive"

      paths = []
      paths.concat(STANDARD_PATHS) if @options.profile != "passive"
      paths.concat(DEEP_PATHS) if @options.profile == "deep"
      paths.concat(@options.paths)
      paths = clean_paths(paths, target, controls)

      requests = []
      requests << { method: "GET", url: target.uri.to_s, follow_redirects: true, purpose: "root" }
      controls.each do |path|
        requests << { method: "GET", url: at_path(target.uri, path).to_s,
                      follow_redirects: false, purpose: "control" }
      end
      paths.each do |path|
        requests << { method: "GET", url: at_path(target.uri, path).to_s,
                      follow_redirects: true, purpose: "probe" }
      end
      if @options.profile == "deep"
        requests << { method: "GET", url: at_path(target.uri, "/robots.txt").to_s,
                      follow_redirects: true, purpose: "discovery" }
        requests << { method: "GET", url: at_path(target.uri, "/sitemap.xml").to_s,
                      follow_redirects: true, purpose: "discovery" }
      end

      planned = requests.size
      capped = requests.first(@options.max_requests)

      {
        target: target.to_h,
        profile: @options.profile,
        adaptive: @options.adaptive,
        scope: scope_decision,
        max_requests: @options.max_requests,
        planned_requests: planned,
        budget_truncated: planned > capped.size,
        estimated_requests: capped.size,
        requests: capped,
        conditional: conditional_notes,
        rate_limit: "#{@options.delay_ms} ms per host between requests; #{@options.threads} target worker(s)",
        authorization: "Only scan assets you are authorized to assess. Confirm scope and ROE first."
      }
    end

    private

    def proceed_with_main?(access)
      return true unless @options.adaptive
      return false if %i[blocked unreachable rate_limited server_error soft_404 auth_wall].include?(access.state)

      true
    end

    def fetch_controls(client, target)
      token = SecureRandom.hex(8)
      paths = ["/php2shell-#{token}.txt"]
      paths << "/php2shell-#{token}.php" unless @options.profile == "passive"

      paths.filter_map do |path|
        break if client.exhausted?

        client.get(at_path(target.uri, path), follow_redirects: false,
                   purpose: path.end_with?(".php") ? "control:php" : "control:txt")
      end
    end

    def main_paths_for(target, probes)
      frameworks = Frameworks.detect(content_probes(probes))
      paths = []
      paths.concat(STANDARD_PATHS) if @options.profile != "passive"

      if @options.profile == "deep"
        paths.concat(DEEP_PATHS)
        frameworks.each do |framework|
          paths.concat(framework.paths)
          paths.concat(FRAMEWORK_VERSION_PATHS.fetch(framework.name, []))
        end
      else
        frameworks.first(2).each { |framework| paths.concat(framework.paths.first(2)) }
      end

      paths.concat(@options.paths)
      clean_paths(paths, target, [])
    end

    def fetch_paths(client, target, paths, probes, trace)
      denied_streak = 0

      paths.each do |path|
        break if client.exhausted?

        probe = client.get(at_path(target.uri, path), follow_redirects: true, purpose: "probe")
        probes << probe
        trace.add("probe #{path}: #{probe.status || probe.error_kind}") if probe.error?

        if probe.rate_limited? || probe.error_kind == :budget
          trace.add("stopping probes: #{probe.error_kind || 'rate limited'}")
          break
        end

        denied_streak = probe.denied? ? denied_streak + 1 : 0
        break if @options.adaptive && denied_streak >= 3 && probes.first&.denied?
      end
    end

    def discover_paths(client, target, probes, trace)
      result = { paths: [], robots: nil, sitemap: nil, disallowed: [] }
      return result if client.exhausted?

      robots = client.get(at_path(target.uri, "/robots.txt"), follow_redirects: true,
                          purpose: "discovery:robots")
      probes << robots
      result[:robots] = {
        status: robots.status,
        usable: robots.usable?,
        error: robots.error,
        sitemaps: [],
        disallowed: []
      }

      sitemap_uris = []
      if robots.usable?
        parsed = Discovery.parse_robots(robots.text_body, target.uri)
        result[:disallowed] = parsed[:disallowed]
        result[:robots][:sitemaps] = parsed[:sitemaps].map(&:to_s)
        result[:robots][:disallowed] = parsed[:disallowed]
        sitemap_uris = parsed[:sitemaps]
      end

      sitemap_uri = sitemap_uris.find { |uri| uri.host.to_s.downcase == target.ascii_host.downcase }
      sitemap_uri ||= at_path(target.uri, "/sitemap.xml")
      return result if client.exhausted?

      sitemap = client.get(sitemap_uri, follow_redirects: true, purpose: "discovery:sitemap")
      probes << sitemap
      result[:sitemap] = { status: sitemap.status, usable: sitemap.usable?, error: sitemap.error }
      return result unless sitemap.usable?

      result[:paths] = Discovery.parse_sitemap(
        sitemap.text_body, sitemap_uri, host: target.ascii_host, limit: MAX_DISCOVERED_PATHS
      )
      trace.add("discovered #{result[:paths].size} .php paths from sitemap")
      result
    end

    def classify_access(probes, root)
      Access.classify(content_probes(probes), root: root)
    end

    def content_probes(probes)
      probes.reject { |probe| probe.purpose.to_s.start_with?("discovery") }
    end

    def surface_of(probes, access, frameworks)
      controls = probes.select { |probe| Access.control?(probe) }
      control_404 = controls.find(&:not_found?)
      soft = access.state == :soft_404
      php_paths = probes.select do |probe|
        probe.request_uri.to_s.split("?", 2).first.to_s.end_with?(".php")
      end
      live_php = !soft && !control_404.nil? && php_paths.any?(&:usable?)
      markers = probes.flat_map(&:php_markers)
      framework = Frameworks.primary(frameworks)

      {
        php_detected: markers.any? || live_php || probes.any?(&:php_fpm_not_found?) || !framework.nil?,
        upload_progress: probes.any?(&:php_cookie?),
        phpinfo_exposed: probes.any?(&:phpinfo?),
        php_errors: probes.any?(&:php_error_page?),
        php_paths_live: live_php,
        framework: framework,
        auth_wall: access.state == :auth_wall
      }
    end

    # Header evidence first because it is exact; phpinfo second because it
    # is authoritative but rarer. A branch-only version (8.2) is kept as a
    # candidate but not silently upgraded to a patch-level claim.
    def extract_version(probes)
      candidates = []
      probes.each do |probe|
        if (value = probe.php_version_from_headers)
          candidates << { version: value[0], source: value[1], url: probe.url, confidence: "high" }
        end
        if (value = probe.php_version_from_phpinfo)
          candidates << { version: value[0], source: value[1], url: probe.url, confidence: "high" }
        end
      end
      candidates.uniq! { |candidate| [candidate[:version], candidate[:source]] }
      return [nil, nil, nil, candidates] if candidates.empty?

      exact = candidates.select { |candidate| candidate[:version].to_s.split(".").length >= 3 }
      chosen = exact.first || candidates.first
      version = Verdict.parse_version(chosen[:version])
      precision = chosen[:version].to_s.split(".").length >= 3 ? :patch : :minor
      [version, chosen[:source], precision, candidates]
    end

    def coverage_of(probes)
      attempted = probes.size
      usable = probes.count(&:usable?)
      {
        attempted: attempted,
        usable: usable,
        denied: probes.count(&:denied?),
        not_found: probes.count(&:not_found?),
        errors: probes.count(&:error?),
        rate_limited: probes.count(&:rate_limited?),
        server_error: probes.count(&:server_error?),
        percent: attempted.zero? ? 0.0 : (usable.to_f / attempted * 100.0).round(1)
      }
    end

    def fingerprint_of(target, probes, environment, access, coverage, candidates,
                       tls, dns, discovery, client)
      content = content_probes(probes)
      cookies = content.flat_map(&:set_cookies)
                       .map { |cookie| cookie.to_s.split(";", 2).first.to_s.split("=", 2).first.to_s }
                       .reject(&:empty?)
                       .uniq

      {
        x_powered_by: content.map(&:x_powered_by).compact.first,
        server: content.map(&:server).compact.first,
        via: content.map { |probe| probe.header("via") }.compact.first,
        edge: environment.edge,
        cdn: environment.cdn,
        waf: environment.waf,
        hosting: environment.hosting,
        cookie_names: cookies,
        statuses: content.map(&:status).compact.uniq.sort,
        probed_paths: content.map(&:request_uri).compact.uniq,
        titles: content.map(&:title).compact.uniq,
        generator: content.map(&:generator).compact.first,
        frameworks: environment.frameworks.map(&:to_h),
        framework_versions: environment.framework_versions,
        php_markers: content.flat_map(&:php_markers).uniq,
        version_candidates: candidates,
        control: access.control,
        coverage: coverage,
        tls: tls,
        dns: dns,
        discovered_paths: discovery[:paths],
        robots: discovery[:robots],
        sitemap: discovery[:sitemap],
        requests: client.requests,
        target: target.to_h
      }
    end

    def clean_paths(paths, target, extra_exclusions)
      excluded = ["/", target.uri.path, *extra_exclusions]
      paths.map { |path| path.to_s.strip }
           .reject(&:empty?)
           .map { |path| path.start_with?("/") ? path : "/#{path}" }
           .reject { |path| excluded.include?(path) }
           .reject { |path| path.include?("..") || path.include?("?") || path.match?(/[\r\n]/) }
           .reject { |path| !Discovery.safe_path?(path) }
           .uniq
    end

    def conditional_notes
      notes = [
        "Framework-specific paths (WordPress/Drupal/Joomla) are added only if the root response identifies the framework.",
        "Deep mode adds robots.txt and sitemap.xml discovery, then at most #{MAX_DISCOVERED_PATHS} same-host .php paths from the sitemap.",
        "If the root and control probes are both denied, adaptive mode stops after the controls and reports BLOCKED instead of guessing."
      ]
      notes << "Custom paths from --paths are appended after the built-in set." unless @options.paths.empty?
      notes
    end

    def at_path(uri, path)
      uri.dup.tap do |copy|
        copy.path = path
        copy.query = nil
        copy.fragment = nil
      end
    end

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
