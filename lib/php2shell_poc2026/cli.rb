# frozen_string_literal: true

require "json"
require "optparse"
require "thread"
require "time"
require "yaml"

require_relative "errors"
require_relative "i18n"
require_relative "next_steps_runner"
require_relative "options"
require_relative "rate_limiter"
require_relative "report"
require_relative "sanitize"
require_relative "scan_result"
require_relative "scanner"
require_relative "scope"
require_relative "target"
require_relative "version"

module PHP2ShellPOC2026
  # Option parsing and exit codes — the only file that talks to the outside
  # world on behalf of a human. Scan orchestration lives in Scanner and
  # presentation in Report; this class exists so the boundary between "what
  # the user asked for" and "what the tool does" stays visible.
  #
  # Exit codes are part of the interface:
  #   0  clear (patched / no PHP) or unverified without --fail-on
  #   1  usage, configuration, or internal error
  #   2  exposed (vulnerable or end-of-life interpreter)
  #   3  inconclusive, when --fail-on inconclusive|any
  #   4  scope violation (--require-scope)
  class CLI
    EXIT_OK           = 0
    EXIT_ERROR        = 1
    EXIT_VULN         = 2
    EXIT_INCONCLUSIVE = 3
    EXIT_SCOPE        = 4

    def initialize(argv)
      @argv   = argv.dup
      @cli    = {}
      @options = nil
      @config_targets = []
      @scope_skipped = 0
      @rate_limiter = nil
    end

    def run
      catch(:early_exit) do
        begin
          parse_options!
          build_options!
          targets = collect_targets
          scope, exclude = load_scopes
          work, skipped = enforce_scope(targets, scope, exclude)
          @scope_skipped = skipped

          if @options.dry_run
            render_plan(work, scope)
            EXIT_OK
          else
            results = scan_all(work)
            meta = render_report(results, scope)
            followup = maybe_run_next_steps(results, meta)
            exit_code(results, followup)
          end
        rescue ScopeError => e
          warn "php2shell-poc2026: scope violation: #{e.message}"
          EXIT_SCOPE
        rescue UsageError => e
          warn "php2shell-poc2026: #{e.message}"
          EXIT_ERROR
        rescue OptionParser::ParseError => e
          warn "php2shell-poc2026: #{e.message}"
          EXIT_ERROR
        rescue Interrupt
          warn "php2shell-poc2026: interrupted"
          EXIT_ERROR
        rescue Errno::EPIPE
          EXIT_OK
        rescue StandardError => e
          warn "php2shell-poc2026: internal error: #{e.class}: #{e.message}"
          warn e.full_message if @options&.verbose
          EXIT_ERROR
        end
      end
    end

    private

    # -- parsing -----------------------------------------------------------

    def parse_options!
      parser = OptionParser.new do |o|
        o.banner = <<~BANNER
          Usage: php2shell-poc2026 [options] URL [URL ...]

          Passive PHP2Shell exposure triage. Ordinary GET requests only; no payloads,
          no exploitation, no state-changing verbs. Only scan assets you are authorized
          to assess.
        BANNER

        o.separator ""
        o.separator "Scanning:"
        o.on("-p", "--profile PROFILE", Options::PROFILES,
             "passive, standard (default) or deep") { |v| @cli[:profile] = v }
        o.on("-d", "--deep", "Alias for --profile deep") { @cli[:profile] = "deep" }
        o.on("-t", "--timeout SECS", Integer, "Per-request read timeout (default: 10)") { |v| @cli[:timeout] = v }
        o.on("--connect-timeout SECS", Integer, "TCP/TLS connect timeout (default: 5)") { |v| @cli[:connect_timeout] = v }
        o.on("--max-redirects N", Integer, "Redirects to follow per probe (default: 5)") { |v| @cli[:max_redirects] = v }
        o.on("--max-body BYTES", "Response body cap, e.g. 512k or 1M (default: 512k)") do |v|
          @cli[:max_body] = parse_bytes(v)
        end
        o.on("--retries N", Integer, "Retries for transient errors (default: 1)") { |v| @cli[:retries] = v }
        o.on("--no-retry-after", "Ignore Retry-After and use exponential backoff") { @cli[:retry_after] = false }
        o.on("--delay MS", Integer, "Minimum delay per host between requests (default: 250)") { |v| @cli[:delay_ms] = v }
        o.on("--threads N", Integer, "Target worker threads (default: 4)") { |v| @cli[:threads] = v }
        o.on("--max-requests N", Integer, "Per-target request budget (default: 25)") { |v| @cli[:max_requests] = v }
        o.on("--no-adaptive", "Continue probing even when the edge blocks every path") { @cli[:adaptive] = false }
        o.on("--path PATH", "Extra path to probe (repeatable)") { |v| (@cli[:paths] ||= []) << v }

        o.separator ""
        o.separator "HTTP:"
        o.on("-H", "--header HEADER", "Extra request header, 'Name: value' (repeatable)") do |v|
          (@cli[:headers] ||= []) << v
        end
        o.on("--cookie STRING", "Cookie header value") { |v| @cli[:cookie] = v }
        o.on("-A", "--user-agent STRING", "User-Agent override") { |v| @cli[:user_agent] = v }
        o.on("--browser-ua", "Use a browser-compatible User-Agent (may bypass bot blocks; authorized use only)") do
          @cli[:browser_ua] = true
        end
        o.on("--proxy URL", "HTTP proxy, e.g. http://127.0.0.1:8080") { |v| @cli[:proxy] = v }
        o.on("--no-proxy", "Ignore HTTP(S)_PROXY/ALL_PROXY environment variables") { @cli[:no_proxy] = true }
        o.on("--basic-auth USER:PASS", "HTTP Basic authentication (same-origin requests only)") { |v| @cli[:basic_auth] = v }
        o.on("--bearer TOKEN", "Bearer token (same-origin requests only)") { |v| @cli[:bearer] = v }
        o.on("--ca-file PATH", "Custom CA bundle for TLS verification") { |v| @cli[:ca_file] = v }
        o.on("-k", "--insecure", "Skip TLS certificate verification") { @cli[:verify_tls] = false }

        o.separator ""
        o.separator "Scope and authorization:"
        o.on("--scope FILE", "Only scan hosts matching this scope file") { |v| @cli[:scope] = v }
        o.on("--exclude FILE", "Skip hosts matching this scope file") { |v| @cli[:exclude] = v }
        o.on("--require-scope", "Fail closed (exit 4) if a target is outside --scope") { @cli[:require_scope] = true }
        o.on("--authorized", "Include offensive/post-exploitation tooling entries") { @cli[:authorized] = true }

        o.separator ""
        o.separator "Reporting:"
        o.on("-f", "--format FORMAT", Options::FORMATS,
             "text (default), json, markdown, sarif, csv or ndjson") { |v| @cli[:format] = v }
        o.on("-j", "--json", "Alias for --format json") { @cli[:format] = "json" }
        o.on("-o", "--output FILE", "Write the report to FILE instead of stdout") { |v| @cli[:output] = v }
        o.on("--compact", "Compact JSON instead of pretty-printing") { @cli[:compact] = true }
        o.on("--no-banner", "Suppress the report banner") { @cli[:no_banner] = true }
        o.on("--no-color", "Disable colour output (also honours NO_COLOR; piped output is plain)") { @cli[:no_color] = true }
        o.on("--evidence", "Include a short body excerpt in JSON/NDJSON evidence") { @cli[:evidence] = true }
        o.on("-q", "--quiet", "Bottom line, findings table and run summary only") { @cli[:quiet] = true }
        o.on("-r", "--redteam", "Include attacker notes") { @cli[:redteam] = true }
        o.on("-c", "--toolchain", "Include relevant tools") { @cli[:toolchain] = true }
        o.on("--toolchain-full", "Include all tools with reasons") { @cli[:toolchain_full] = true }
        o.on("-v", "--verbose", "Add technical details, attack-path notes, defender checks and request trace") do
          @cli[:verbose] = true
        end
        o.on("-en", "English text report (short for --lang en)") { @cli[:locale] = "en" }
        o.on("-zh", "Chinese text report (short for --lang zh)") { @cli[:locale] = "zh" }
        o.on("--lang LOCALE", "Text report language: auto, en or zh (default: device language)") do |v|
          @cli[:locale] = v
        end
        o.on("--fail-on MODE", Options::FAIL_ON,
             "exposed (default), inconclusive, any or never") { |v| @cli[:fail_on] = v }
        o.on("--no-interactive", "Do not ask to run safe follow-up checks") { @cli[:interactive] = false }
        o.on("--yes", "Run safe follow-up checks without asking") { @cli[:yes] = true }
        o.on("--dry-run", "Print the request plan and exit without opening a socket") { @cli[:dry_run] = true }
        o.on("-C", "--config FILE", "Load defaults from a YAML config file") { |v| @cli[:config] = v }

        o.separator ""
        o.on("-V", "--version", "Print version and exit") do
          puts "php2shell-poc2026 #{VERSION}"
          throw :early_exit, EXIT_OK
        end
        o.on("-h", "--help", "Show this help") do
          puts o
          throw :early_exit, EXIT_OK
        end

        o.separator ""
        o.separator "Exit codes: 0 clear/unverified, 1 error, 2 exposed, 3 inconclusive, 4 scope violation."
      end

      parser.parse!(@argv)
    end

    def build_options!
      config = {}
      if @cli[:config]
        config, @config_targets = load_config(@cli[:config])
      end

      merged = config.merge(@cli)
      merged.delete(:config)
      merged[:locale] = detect_locale if merged[:locale].nil? || merged[:locale].to_s.strip.empty? ||
                                          merged[:locale].to_s.strip.downcase == "auto"
      @options = Options.new(**merged)
      @options.config = @cli[:config] && File.expand_path(@cli[:config])
      @options.validate!

      # Localisation is deliberately limited to the human-readable text
      # report. Machine formats keep their canonical English messages so a
      # Chinese workstation cannot silently change a JSON/SARIF contract.
      @options.locale = "en" unless @options.format == "text"
      I18n.locale = @options.locale

      if @options.require_scope && @options.scope.nil?
        raise UsageError, "--require-scope needs --scope FILE"
      end
      if @options.format == "json"
        @options.no_banner = true
      end

      @rate_limiter = RateLimiter.new(@options.delay_ms)
    end

    def detect_locale
      I18n.detect
    end

    def load_config(path)
      absolute = File.expand_path(path)
      raise UsageError, "config file not found: #{path}" unless File.file?(absolute)

      raw = YAML.safe_load(File.read(absolute), permitted_classes: [], aliases: false) || {}
      raise UsageError, "config must be a YAML mapping: #{path}" unless raw.is_a?(Hash)

      config = raw.each_with_object({}) { |(key, value), acc| acc[key.to_sym] = value }
      targets = config.delete(:targets)
      config[:profile] = "deep" if config.delete(:deep)
      config[:format]  = "json" if config.delete(:json)

      %i[scope exclude ca_file output].each do |key|
        value = config[key]
        next unless value.is_a?(String) && !value.strip.empty?

        config[key] = File.expand_path(value, File.dirname(absolute))
      end

      [config, Array(targets).map(&:to_s)]
    rescue Psych::Exception => e
      raise UsageError, "invalid config YAML #{path}: #{e.message}"
    end

    def parse_bytes(value)
      match = value.to_s.strip.downcase.match(/\A(\d+)\s*(b|k|kb|m|mb)?\z/)
      raise UsageError, "invalid byte size: #{value.inspect} (use e.g. 512k or 1M)" unless match

      multiplier = case match[2]
                   when "k", "kb" then 1024
                   when "m", "mb" then 1024 * 1024
                   else 1
                   end
      match[1].to_i * multiplier
    end

    # -- targets and scope -------------------------------------------------

    def collect_targets
      raw = @argv.empty? ? @config_targets : @argv
      raise UsageError, "at least one URL is required (see --help)" if raw.empty?

      targets = []
      seen = {}
      raw.each do |value|
        target = Target.parse(value)
        next if seen[target.uri.to_s]

        seen[target.uri.to_s] = true
        targets << target
      rescue UsageError => e
        warn "php2shell-poc2026: skipping #{value.inspect}: #{e.message}" unless @options.quiet
      end

      raise UsageError, "no valid targets after parsing" if targets.empty?

      targets
    end

    def load_scopes
      scope   = @options.scope ? Scope.load(@options.scope) : Scope.empty
      exclude = @options.exclude ? Scope.load(@options.exclude) : Scope.empty
      if @options.require_scope && scope.empty?
        raise UsageError, "--require-scope needs a non-empty --scope file"
      end

      [scope, exclude]
    end

    def enforce_scope(targets, scope, exclude)
      work = []
      skipped = 0

      targets.each do |target|
        decision = scope.include?(target)
        unless decision.allowed
          if @options.require_scope
            raise ScopeError, "#{target.display} — #{decision.reason}"
          end

          skipped += 1
          warn "php2shell-poc2026: skipping out-of-scope target #{target.display} — #{decision.reason}" unless @options.quiet
          next
        end

        if exclude.include?(target).allowed && !exclude.empty?
          skipped += 1
          warn "php2shell-poc2026: excluding #{target.display} (matches --exclude)" unless @options.quiet
          next
        end

        work << [target, decision.to_h]
      end

      [work, skipped]
    end

    # -- scanning ----------------------------------------------------------

    def scan_all(work)
      results = Array.new(work.size)
      queue = Queue.new
      work.each_with_index { |(target, decision), index| queue << [index, target, decision] }
      queue.close

      workers = [[@options.threads, work.size].min, 1].max
      threads = Array.new(workers) do
        Thread.new do
          scanner = Scanner.new(options: @options, rate_limiter: @rate_limiter)
          while (job = queue.pop)
            index, target, decision = job
            begin
              results[index] = scanner.scan(target, scope_decision: decision)
            rescue StandardError => e
              results[index] = ScanResult.failed(target, e, @options, meta: { scope: decision })
            end
          end
        end
      end
      threads.each(&:join)
      results.compact
    end

    # -- output ------------------------------------------------------------

    def render_report(results, scope)
      meta = {
        generated_at: Time.now.utc.iso8601,
        profile: @options.profile,
        scope: scope.to_h,
        scope_skipped: @scope_skipped
      }
      output = Report.render(results, @options, meta: meta)
      write_output(output)
      meta
    end

    # The report is advisory; this is the "proceed?" step. Only text reports
    # on an interactive terminal ask. Machine formats, files, quiet mode and
    # dry runs never prompt.
    def maybe_run_next_steps(results, meta)
      return nil unless @options.format == "text"
      return nil if @options.quiet || @options.dry_run
      return nil if @options.output && !@options.yes
      return nil unless @options.interactive || @options.yes
      return nil unless @options.yes || $stdout.tty?

      $stdout.flush
      NextStepsRunner.run(results, @options, meta: meta, input: $stdin, out: $stdout)
    end

    def render_plan(work, scope)
      if @options.format == "json"
        plans = work.map do |target, decision|
          Scanner.new(options: @options, rate_limiter: @rate_limiter)
                 .plan(target, scope_decision: decision)
        end
        payload = {
          schema_version: "3.0",
          tool: { name: "php2shell-poc2026", version: VERSION, homepage: HOMEPAGE },
          generated_at: Time.now.utc.iso8601,
          dry_run: true,
          options: @options.public_h,
          scope: scope.to_h,
          skipped: @scope_skipped,
          plans: plans
        }
        write_output(JSON.pretty_generate(payload) + "\n")
        return
      end

      unless @options.format == "text"
        raise UsageError, "--dry-run supports text or json output (got #{@options.format.inspect})"
      end

      lines = []
      lines << "php2shell-poc2026 #{VERSION} — dry-run request plan" unless @options.no_banner
      lines << "profile #{@options.profile} · #{work.size} target#{work.size == 1 ? '' : 's'} · " \
               "#{@scope_skipped} skipped outside scope"
      lines << "No socket will be opened. Review this plan against your authorization and ROE."
      lines << ""

      work.each do |target, decision|
        plan = Scanner.new(options: @options, rate_limiter: @rate_limiter)
                      .plan(target, scope_decision: decision)
        lines << plan[:target][:display]
        lines << "  scope       : #{decision[:reason]}"
        budget_note = plan[:budget_truncated] ? " (capped from #{plan[:planned_requests]})" : ""
        lines << "  profile     : #{plan[:profile]} · adaptive #{plan[:adaptive]} · " \
                 "max requests #{plan[:max_requests]} · estimated #{plan[:estimated_requests]}#{budget_note}"
        lines << "  rate limit  : #{plan[:rate_limit]}"
        lines << "  requests:"
        plan[:requests].each do |request|
          suffix = request[:follow_redirects] ? " (follow redirects)" : ""
          lines << "    #{request[:method]} #{request[:url]} — #{request[:purpose]}#{suffix}"
        end
        unless plan[:conditional].empty?
          lines << "  conditional:"
          plan[:conditional].each { |note| lines << "    - #{note}" }
        end
        lines << "  authorization: #{plan[:authorization]}"
        lines << ""
      end

      write_output(lines.join("\n") + "\n")
    end

    def write_output(output)
      if @options.output.nil? || @options.output == "-"
        $stdout.write(output)
      else
        path = File.expand_path(@options.output)
        File.write(path, output)
        warn "php2shell-poc2026: wrote #{path}" unless @options.quiet
      end
    end

    def exit_code(results, followup = nil)
      all = results + Array(followup)
      return EXIT_ERROR if all.any?(&:error)

      exposed    = all.any?(&:exposed?)
      unverified = all.any?(&:unverified?)

      case @options.fail_on
      when "never"
        EXIT_OK
      when "exposed"
        exposed ? EXIT_VULN : EXIT_OK
      when "inconclusive", "any"
        return EXIT_VULN if exposed
        unverified ? EXIT_INCONCLUSIVE : EXIT_OK
      else
        EXIT_ERROR
      end
    end
  end
end
