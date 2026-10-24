# frozen_string_literal: true

require "ipaddr"
require "uri"
require_relative "idn"

module PHP2ShellPOC2026
  # Authorization is a feature, not paperwork. A scope file turns "please
  # only scan what you are allowed to scan" into something the process can
  # enforce before the first packet leaves the host.
  #
  # Accepted lines:
  #   example.com          exact host and subdomains
  #   *.example.com        subdomains only
  #   192.0.2.10           single IPv4/IPv6 address
  #   192.0.2.0/24         CIDR range
  #   https://example.com  host extracted from a URL
  #   # comment            ignored
  class Scope
    Decision = Struct.new(:allowed, :pattern, :reason, keyword_init: true) do
      def to_h
        { allowed: allowed, pattern: pattern, reason: reason }
      end
    end

    Pattern = Struct.new(:raw, :type, :value, :subdomains, keyword_init: true)

    attr_reader :patterns

    def initialize(patterns = [])
      @patterns = patterns
    end

    def self.empty
      new([])
    end

    def self.load(path)
      raise UsageError, "scope file not found: #{path}" unless File.file?(path)

      parse(File.readlines(path, chomp: true))
    rescue SystemCallError => e
      raise UsageError, "cannot read scope file #{path}: #{e.message}"
    end

    def self.parse(lines)
      patterns = lines.filter_map { |line| parse_line(line) }
      new(patterns)
    end

    def self.parse_line(line)
      text = line.to_s.strip
      text = text.sub(/#.*\z/, "").strip
      return nil if text.empty?

      if text.include?("://")
        uri = URI.parse(text)
        host = uri.host
        return nil if host.nil?

        return host_pattern(host)
      end

      if text.include?("/") && !text.start_with?("/")
        begin
          network = IPAddr.new(text)
          return Pattern.new(raw: text, type: :cidr, value: network, subdomains: true)
        rescue IPAddr::InvalidAddressError, ArgumentError
          # Fall through: it may be a host with a path.
        end
      end

      begin
        address = IPAddr.new(text)
        return Pattern.new(raw: text, type: :ip, value: address, subdomains: false)
      rescue IPAddr::InvalidAddressError, ArgumentError
        # Not an IP.
      end

      host_pattern(text)
    rescue URI::InvalidURIError
      nil
    end

    def self.host_pattern(text)
      host = text.to_s.strip
      host = host.sub(%r{\A//}, "")
      host = host.split("/", 2).first.to_s
      host = host.split(":", 2).first.to_s unless host.start_with?("[")
      host = host.sub(/\.\z/, "").downcase
      return nil if host.empty?

      if host.start_with?("*.")
        Pattern.new(raw: text, type: :wildcard, value: Idn.to_ascii(host[2..-1]), subdomains: true)
      else
        Pattern.new(raw: text, type: :domain, value: Idn.to_ascii(host), subdomains: true)
      end
    end

    def empty?
      @patterns.empty?
    end

    def include?(target)
      return Decision.new(allowed: true, pattern: nil, reason: "no scope file supplied") if empty?

      host = host_of(target)
      return Decision.new(allowed: false, pattern: nil, reason: "target has no host") if host.nil?

      address = ip_address(host)

      @patterns.each do |pattern|
        next unless match?(pattern, host, address)

        return Decision.new(allowed: true, pattern: pattern.raw,
                            reason: "matches scope pattern #{pattern.raw}")
      end

      Decision.new(allowed: false, pattern: nil,
                   reason: "#{host} matches no pattern in the scope file")
    end

    def exclude?(target, exclude_scope)
      return false if exclude_scope.nil? || exclude_scope.empty?

      decision = exclude_scope.include?(target)
      decision.allowed
    end

    def to_h
      { patterns: @patterns.map(&:raw) }
    end

    private

    def host_of(target)
      text = target.to_s.strip
      return nil if text.empty?

      if text.include?("://")
        host = URI.parse(text).host
        host = host[1..-2] if host&.start_with?("[") && host.end_with?("]")
        host
      else
        candidate = text.split("/", 2).first.to_s
        candidate = candidate[1..-2] if candidate.start_with?("[") && candidate.end_with?("]")
        candidate.split(":", 2).first
      end
    rescue URI::InvalidURIError
      nil
    end

    def ip_address(host)
      IPAddr.new(host)
    rescue IPAddr::InvalidAddressError, ArgumentError
      nil
    end

    def match?(pattern, host, address)
      case pattern.type
      when :cidr, :ip
        return false if address.nil?

        pattern.type == :ip ? address == pattern.value : pattern.value.include?(address)
      else
        domain_match?(pattern, host)
      end
    end

    def domain_match?(pattern, host)
      candidate = Idn.to_ascii(host).downcase.sub(/\.\z/, "")
      base      = pattern.value

      if pattern.type == :wildcard
        candidate.end_with?(".#{base}")
      else
        candidate == base || candidate.end_with?(".#{base}")
      end
    end
  end
end
