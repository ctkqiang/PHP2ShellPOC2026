# frozen_string_literal: true

require "uri"
require_relative "errors"
require_relative "version"

module PHP2ShellPOC2026
  # Everything the scanner can be told to do, in one validated object.
  # Keeping defaults and coercion here means the CLI, the config file and
  # the tests all speak the same language; a typo in an option name fails
  # once, at the boundary, instead of silently doing nothing.
  class Options
    ATTRS = %i[
      profile timeout connect_timeout verify_tls max_redirects max_body retries
      retry_after delay_ms threads max_requests adaptive
      headers cookie user_agent proxy no_proxy basic_auth bearer ca_file
      paths scope exclude require_scope
      format output compact no_banner no_color evidence quiet
      redteam toolchain toolchain_full authorized verbose fail_on dry_run config
    ].freeze

    PROFILES = %w[passive standard deep].freeze
    FORMATS  = %w[text json markdown sarif csv ndjson].freeze
    FAIL_ON  = %w[exposed inconclusive any never].freeze

    attr_accessor(*ATTRS)

    def self.defaults
      {
        profile: "standard",
        timeout: 10,
        connect_timeout: 5,
        verify_tls: true,
        max_redirects: 5,
        max_body: 524_288,
        retries: 1,
        retry_after: true,
        delay_ms: 250,
        threads: 4,
        max_requests: 25,
        adaptive: true,
        headers: {},
        cookie: nil,
        user_agent: USER_AGENT,
        proxy: nil,
        no_proxy: false,
        basic_auth: nil,
        bearer: nil,
        ca_file: nil,
        paths: [],
        scope: nil,
        exclude: nil,
        require_scope: false,
        format: "text",
        output: nil,
        compact: false,
        no_banner: false,
        no_color: false,
        evidence: false,
        quiet: false,
        redteam: false,
        toolchain: false,
        toolchain_full: false,
        authorized: false,
        verbose: false,
        fail_on: "exposed",
        dry_run: false,
        config: nil
      }
    end

    def initialize(**kwargs)
      self.class.defaults.each { |key, value| send("#{key}=", value) }
      merge!(kwargs)
    end

    def self.from_hash(hash)
      new(**hash)
    end

    def merge!(hash)
      hash.each do |key, value|
        key = key.to_sym
        next if key == :deep # handled by the CLI as a profile alias
        unless ATTRS.include?(key)
          raise UsageError, "unknown option: #{key}"
        end

        send("#{key}=", value)
      end
      normalize!
      self
    end

    def merge(hash)
      dup.merge!(hash)
    end

    def initialize_copy(other)
      super
      @headers = other.headers.dup
      @paths   = other.paths.dup
    end

    def normalize!
      self.profile = profile.to_s
      self.profile = "deep" if profile == "deep"
      self.format  = format.to_s
      self.fail_on = fail_on.to_s
      self.toolchain = true if toolchain_full

      self.headers = normalize_headers(headers)
      self.paths   = Array(paths).map(&:to_s).reject(&:empty?).uniq

      self.timeout         = integer(timeout, :timeout)
      self.connect_timeout = integer(connect_timeout, :connect_timeout)
      self.max_redirects   = integer(max_redirects, :max_redirects)
      self.max_body        = integer(max_body, :max_body)
      self.retries         = integer(retries, :retries)
      self.delay_ms        = integer(delay_ms, :delay_ms)
      self.threads         = integer(threads, :threads)
      self.max_requests    = integer(max_requests, :max_requests)

      self.verify_tls   = boolean(verify_tls)
      self.retry_after  = boolean(retry_after)
      self.adaptive     = boolean(adaptive)
      self.no_proxy     = boolean(no_proxy)
      self.require_scope = boolean(require_scope)
      self.compact      = boolean(compact)
      self.no_banner    = boolean(no_banner)
      self.no_color     = boolean(no_color)
      self.evidence     = boolean(evidence)
      self.quiet        = boolean(quiet)
      self.redteam      = boolean(redteam)
      self.toolchain    = boolean(toolchain)
      self.toolchain_full = boolean(toolchain_full)
      self.authorized   = boolean(authorized)
      self.verbose      = boolean(verbose)
      self.dry_run      = boolean(dry_run)

      self.scope   = blank_to_nil(scope)
      self.exclude = blank_to_nil(exclude)
      self.output  = blank_to_nil(output)
      self.config  = blank_to_nil(config)
      self.proxy   = blank_to_nil(proxy)
      self.cookie  = blank_to_nil(cookie)
      self.basic_auth = blank_to_nil(basic_auth)
      self.bearer  = blank_to_nil(bearer)
      self.ca_file = blank_to_nil(ca_file)
      self.user_agent = USER_AGENT if user_agent.nil? || user_agent.to_s.strip.empty?
      self.user_agent = user_agent.to_s
      self
    end

    def validate!
      unless PROFILES.include?(profile)
        raise UsageError, "invalid profile #{profile.inspect} (choose #{PROFILES.join(', ')})"
      end
      unless FORMATS.include?(format)
        raise UsageError, "invalid format #{format.inspect} (choose #{FORMATS.join(', ')})"
      end
      unless FAIL_ON.include?(fail_on)
        raise UsageError, "invalid --fail-on #{fail_on.inspect} (choose #{FAIL_ON.join(', ')})"
      end

      positive!(timeout, "timeout")
      positive!(connect_timeout, "connect-timeout")
      positive!(max_body, "max-body", minimum: 1024)
      positive!(max_requests, "max-requests", minimum: 1, maximum: 200)
      range!(max_redirects, "max-redirects", 0, 20)
      range!(retries, "retries", 0, 5)
      range!(delay_ms, "delay-ms", 0, 60_000)
      range!(threads, "threads", 1, 32)

      if proxy && !proxy.empty?
        uri = URI.parse(proxy)
        unless uri.is_a?(URI::HTTP) && uri.host
          raise UsageError, "invalid proxy #{proxy.inspect} — expected http://host:port"
        end
      end

      if basic_auth && !basic_auth.include?(":")
        raise UsageError, "--basic-auth must be USER:PASSWORD"
      end

      headers.each do |name, value|
        if name.match?(/[\r\n:]/) || value.match?(/[\r\n]/)
          raise UsageError, "invalid header (CR/LF or ':' in name): #{name.inspect}"
        end
      end

      [paths].flatten.each do |path|
        unless path.start_with?("/")
          raise UsageError, "custom path must start with '/': #{path.inspect}"
        end
        if path.match?(/[\r\n]/)
          raise UsageError, "custom path contains a newline: #{path.inspect}"
        end
      end

      self
    end

    # Safe for logs, JSON metadata and bug reports. Credentials and
    # authorization headers never leave the process in a report.
    def public_h
      hash = ATTRS.each_with_object({}) { |key, acc| acc[key] = send(key) }
      hash[:headers] = headers.each_with_object({}) do |(name, value), acc|
        acc[name] = sensitive_header?(name) ? "***" : value
      end
      hash[:cookie]     = "***" if cookie
      hash[:basic_auth] = "***" if basic_auth
      hash[:bearer]     = "***" if bearer
      hash
    end

    def to_h
      ATTRS.each_with_object({}) { |key, acc| acc[key] = send(key) }
    end

    private

    def normalize_headers(value)
      case value
      when nil
        {}
      when Hash
        value.each_with_object({}) do |(name, val), acc|
          acc[name.to_s.strip] = val.to_s
        end
      when Array
        value.each_with_object({}) do |line, acc|
          name, val = line.to_s.split(":", 2)
          next if val.nil?

          acc[name.to_s.strip] = val.to_s.strip
        end
      else
        raise UsageError, "headers must be a mapping or a list of 'Name: value' strings"
      end
    end

    def sensitive_header?(name)
      name.to_s.match?(/authorization|cookie|token|secret|api[-_]?key/i)
    end

    def integer(value, name)
      Integer(value)
    rescue ArgumentError, TypeError
      raise UsageError, "#{name} must be an integer (got #{value.inspect})"
    end

    def boolean(value)
      return value if value == true || value == false
      return true if value.to_s.match?(/\A(true|yes|1|on)\z/i)
      return false if value.to_s.match?(/\A(false|no|0|off)\z/i)

      raise UsageError, "expected a boolean (got #{value.inspect})"
    end

    def blank_to_nil(value)
      text = value.to_s.strip
      text.empty? ? nil : text
    end

    def positive!(value, name, minimum: 1, maximum: nil)
      unless value.is_a?(Integer) && value >= minimum && (maximum.nil? || value <= maximum)
        range = maximum ? "#{minimum}..#{maximum}" : ">= #{minimum}"
        raise UsageError, "--#{name} must be an integer #{range} (got #{value.inspect})"
      end
    end

    def range!(value, name, minimum, maximum)
      unless value.is_a?(Integer) && value.between?(minimum, maximum)
        raise UsageError, "--#{name} must be an integer #{minimum}..#{maximum} (got #{value.inspect})"
      end
    end
  end
end
