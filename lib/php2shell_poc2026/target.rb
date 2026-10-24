# frozen_string_literal: true

require "ipaddr"
require "uri"
require_relative "errors"
require_relative "idn"
require_relative "sanitize"

module PHP2ShellPOC2026
  # One target, normalised once. Everything downstream (scope, HTTP, reports)
  # reads this object instead of re-parsing user input and disagreeing about
  # what the host actually is.
  class Target
    DEFAULT_PORTS = { "http" => 80, "https" => 443 }.freeze

    attr_reader :original, :display, :uri, :host, :ascii_host, :port, :scheme

    def initialize(original:, display:, uri:, host:, ascii_host:, port:, scheme:)
      @original    = original
      @display     = display
      @uri         = uri
      @host        = host
      @ascii_host  = ascii_host
      @port        = port
      @scheme      = scheme
    end

    def self.parse(raw)
      original = raw.to_s.strip
      original = original[1..-2] if original.length >= 2 && %w[" '].include?(original[0]) && original[-1] == original[0]
      raise UsageError, "empty target" if original.empty?

      text = original
      text = "https:#{text}" if text.start_with?("//")
      text = "https://#{text}" unless text.include?("://")

      # A bare IPv6 literal needs brackets before URI will accept it.
      if !text.include?("://[") && text.match?(/\Ahttps?:\/\/[0-9a-fA-F:]+\z/)
        begin
          IPAddr.new(text.split("://", 2).last)
          text = text.sub("://", "://[") + "]"
        rescue IPAddr::InvalidAddressError, ArgumentError
          # Not an IP literal; leave it alone.
        end
      end

      scheme, rest = text.split("://", 2)
      scheme = scheme.to_s.downcase
      unless DEFAULT_PORTS.key?(scheme)
        raise UsageError, "not an http(s) URL: #{original}"
      end

      authority, path_and_query = rest.split("/", 2)
      raise UsageError, "target has no host: #{original}" if authority.nil? || authority.empty?
      raise UsageError, "credentials in URLs are not supported; use --basic-auth or --bearer" if authority.include?("@")

      host, port = split_authority(authority, scheme)
      validate_host!(host, original)

      ascii_host = Idn.to_ascii(host)
      validate_ascii_host!(ascii_host, original)

      path, query = split_path(path_and_query)
      path = "/" if path.nil? || path.empty?
      raise UsageError, "target path must start with '/': #{original}" unless path.start_with?("/")
      raise UsageError, "control characters in target: #{original}" if path.match?(/[\u0000-\u001F\u007F]/)

      host_for_uri = ascii_host.include?(":") && !ascii_host.start_with?("[") ? "[#{ascii_host}]" : ascii_host
      port_part    = port == DEFAULT_PORTS[scheme] ? "" : ":#{port}"
      query_part   = query.nil? || query.empty? ? "" : "?#{query}"
      uri = URI.parse("#{scheme}://#{host_for_uri}#{port_part}#{path}#{query_part}")

      display_host = host.include?(":") && !host.start_with?("[") ? "[#{host}]" : host
      display = "#{scheme}://#{display_host}#{port_part}#{path}#{query_part}"

      new(original: original, display: display, uri: uri, host: host,
          ascii_host: ascii_host, port: port, scheme: scheme)
    rescue URI::InvalidURIError => e
      raise UsageError, "invalid target #{original.inspect}: #{e.message}"
    end

    def self.split_authority(authority, scheme)
      if authority.start_with?("[")
        closing = authority.index("]")
        raise UsageError, "unclosed IPv6 literal in target" if closing.nil?

        host = authority[1...closing]
        remainder = authority[(closing + 1)..-1].to_s
        port = remainder.start_with?(":") ? parse_port(remainder[1..-1], scheme) : DEFAULT_PORTS[scheme]
        [host, port]
      else
        host, port_text = authority.split(":", 2)
        port = port_text.nil? || port_text.empty? ? DEFAULT_PORTS[scheme] : parse_port(port_text, scheme)
        [host, port]
      end
    end

    def self.parse_port(text, scheme)
      port = Integer(text, 10)
      raise UsageError, "port out of range: #{text}" unless port.between?(1, 65_535)

      port
    rescue ArgumentError
      raise UsageError, "invalid port: #{text.inspect} (scheme #{scheme})"
    end

    def self.split_path(path_and_query)
      return ["/", nil] if path_and_query.nil? || path_and_query.empty?

      path, query = path_and_query.split("?", 2)
      ["/#{path}".gsub(%r{/+}, "/"), query]
    end

    def self.validate_host!(host, original)
      raise UsageError, "target has no host: #{original}" if host.nil? || host.empty?
      raise UsageError, "control characters in target host: #{original}" if host.match?(/[\u0000-\u0020\u007F]/)
      raise UsageError, "invalid characters in target host: #{original}" if host.match?(/[<>"{}|\\^`]/)
    end

    def self.validate_ascii_host!(host, original)
      raise UsageError, "host is empty after IDN conversion: #{original}" if host.nil? || host.empty?

      labels = host.sub(/\.\z/, "").split(".")
      labels.each do |label|
        raise UsageError, "hostname label too long: #{original}" if label.bytesize > 63
      end
      raise UsageError, "hostname too long: #{original}" if host.bytesize > 253
    end

    def ip?
      IPAddr.new(ascii_host)
      true
    rescue IPAddr::InvalidAddressError, ArgumentError
      false
    end

    def international?
      Idn.international?(host)
    end

    def default_port?
      port == DEFAULT_PORTS[scheme]
    end

    def authority
      host_for_uri = ascii_host.include?(":") ? "[#{ascii_host}]" : ascii_host
      default_port? ? host_for_uri : "#{host_for_uri}:#{port}"
    end

    def to_h
      {
        target: original,
        display: display,
        url: uri.to_s,
        scheme: scheme,
        host: host,
        ascii_host: ascii_host,
        port: port,
        international: international?,
        ip: ip?
      }
    end

    def to_s
      display
    end
  end
end
