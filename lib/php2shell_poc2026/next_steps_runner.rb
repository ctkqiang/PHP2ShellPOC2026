# frozen_string_literal: true

require "open3"
require_relative "http_client"
require_relative "report"
require_relative "sanitize"
require_relative "scanner"
require_relative "version"

module PHP2ShellPOC2026
  # Runs the safe part of the report's NEXT STEPS after the human says yes.
  # It deliberately does not execute arbitrary reported shell strings:
  # response/TLS/DNS checks use the data the scan already collected, SARIF is
  # rendered in-process, and active tools stay behind an explicit
  # --authorized prompt.
  module NextStepsRunner
    NEUTRAL_UA = "curl/8.7.1"

    def self.run(results, options, meta:, input: $stdin, out: $stdout)
      out.puts
      out.puts "  AUTOMATED NEXT STEPS"
      out.puts "  Safe checks only: fresh response, TLS, DNS and a SARIF file."
      active_note = if options.authorized
                      "  Browser-UA retry and active tools are enabled by --authorized."
                    else
                      "  Active tools and a browser-UA retry require --authorized."
                    end
      out.puts active_note

      unless options.yes
        out.print "  Proceed? [y/N] "
        out.flush if out.respond_to?(:flush)
        answer = input.gets
        out.puts
        return nil unless answer && answer.strip.match?(/\A(?:y|yes)\z/i)
      end

      out.puts "  Running safe checks..."
      results.each { |result| verify(result, options, out: out) }
      write_sarif(results, options, meta: meta, out: out)

      retry_results = maybe_browser_retry(results, options, out: out)
      maybe_nuclei(results, options, input: input, out: out) if options.authorized

      out.puts
      out.puts "  Done. Re-scan after the PHP upgrade; scope enforcement needs a scope file."
      retry_results
    rescue Interrupt
      out.puts
      out.puts "  Interrupted."
      nil
    end

    def self.verify(result, options, out:)
      out.puts
      out.puts "  #{Sanitize.terminal(result.target.display)}"

      verify_response(result, options, out: out)
      verify_tls(result, out: out)
      verify_dns(result, out: out)
    end

    def self.verify_response(result, options, out:)
      opts = options.dup
      opts.user_agent = NEUTRAL_UA
      opts.browser_ua = false
      opts.max_requests = 5
      opts.verbose = false
      opts.delay_ms = 0

      probe = HttpClient.new(options: opts).get(result.target.uri)
      if probe.error?
        out.puts "  Fresh response: error — #{Sanitize.terminal(probe.error, max: 160)}"
        return
      end

      bits = ["HTTP #{probe.status}"]
      bits << "server #{Sanitize.header(probe.server, max: 80)}" if probe.server
      if probe.x_powered_by
        powered = Sanitize.header(probe.x_powered_by, max: 80)
        bits << if powered.match?(/\APHP\//i)
                  "PHP #{powered.sub(/\APHP\//i, '')}"
                else
                  "X-Powered-By #{powered}"
                end
      end
      out.puts "  Fresh response: #{bits.join(' · ')}"
    rescue StandardError => e
      out.puts "  Fresh response: error — #{e.class}: #{e.message}"
    end

    def self.verify_tls(result, out:)
      cert = result.fingerprint[:tls]
      unless cert
        out.puts "  TLS: no certificate captured"
        return
      end

      out.puts "  TLS: #{cert[:subject] || 'unknown subject'} · issuer #{cert[:issuer] || 'unknown'} · " \
               "expires #{cert[:not_after] || 'unknown'}"
      san = Array(cert[:san])
      out.puts "       SAN: #{san.join(', ')}" unless san.empty?
    end

    def self.verify_dns(result, out:)
      dns = result.fingerprint[:dns]
      unless dns
        out.puts "  DNS: not captured"
        return
      end

      addresses = Array(dns[:addresses])
      if addresses.empty?
        suffix = dns[:error] ? " (#{dns[:error]})" : ""
        out.puts "  DNS: no addresses#{suffix}"
      else
        out.puts "  DNS: #{addresses.join(', ')}"
      end
    end

    def self.write_sarif(results, options, meta:, out:)
      path = File.expand_path("php2shell.sarif")
      sarif_options = options.dup
      sarif_options.format = "sarif"
      sarif_options.output = nil
      sarif_options.no_banner = true
      body = Report.render(results, sarif_options, meta: meta)
      File.write(path, body)
      out.puts
      out.puts "  SARIF: wrote #{path}"
    rescue StandardError => e
      out.puts "  SARIF: failed — #{e.class}: #{e.message}"
    end

    def self.maybe_browser_retry(results, options, out:)
      blocked = results.select do |result|
        result.verdict.reason_code == :blocked && !options.browser_ua
      end
      return [] if blocked.empty?

      unless options.authorized
        out.puts
        out.puts "  Browser-UA retry skipped: add --authorized to enable it."
        return []
      end

      out.puts
      out.puts "  Browser-UA retry (authorized):"
      retry_results = []
      blocked.each do |result|
        retry_options = options.dup
        retry_options.browser_ua = true
        retry_options.user_agent = BROWSER_USER_AGENT
        retry_options.max_requests = [options.max_requests, 12].min
        retry_options.verbose = false

        retry_result = Scanner.new(options: retry_options).scan(result.target)
        retry_results << retry_result
        answer = retry_result.hackability.answer.to_s.upcase
        version = retry_result.verdict.version ? retry_result.verdict.version.to_s : "unknown"
        out.puts "    #{result.target.display}: #{answer} · PHP #{version} · #{retry_result.verdict.label}"
      rescue StandardError => e
        out.puts "    #{result.target.display}: retry failed — #{e.class}: #{e.message}"
      end
      retry_results
    end

    def self.maybe_nuclei(results, options, input:, out:)
      unless command_available?("nuclei")
        out.puts
        out.puts "  nuclei: not installed; active check skipped."
        return
      end
      return unless input.respond_to?(:tty?) && input.tty?

      out.puts
      out.print "  Also run active nuclei tech detection? [y/N] "
      out.flush if out.respond_to?(:flush)
      answer = input.gets
      out.puts
      return unless answer && answer.strip.match?(/\A(?:y|yes)\z/i)

      results.each do |result|
        out.puts "  nuclei #{result.target.display}:"
        stdout, stderr, status = Open3.capture3("nuclei", "-u", result.target.uri.to_s, "-t", "tech-detect")
        out.puts stdout unless stdout.empty?
        out.puts stderr unless stderr.empty?
        out.puts "  exit #{status.exitstatus}"
      end
    rescue StandardError => e
      out.puts "  nuclei failed — #{e.class}: #{e.message}"
    end

    def self.command_available?(name)
      ENV["PATH"].to_s.split(File::PATH_SEPARATOR).any? do |dir|
        path = File.join(dir, name)
        File.file?(path) && File.executable?(path)
      end
    end
  end
end
