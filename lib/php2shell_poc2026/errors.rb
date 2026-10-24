# frozen_string_literal: true

require "openssl"
require "net/http"
require "timeout"
require "uri"

module PHP2ShellPOC2026
  # Base class so callers can rescue the tool's own failures without
  # accidentally swallowing programming errors from elsewhere.
  class Error < StandardError; end

  # Bad flags, bad config, bad target syntax.
  class UsageError < Error; end

  # A target is outside the authorized scope. Deliberately separate from
  # UsageError so CI can distinguish "you typed the command wrong" from
  # "you asked me to touch something you did not authorize".
  class ScopeError < Error; end

  # Network failures are data, not crashes: a dead path degrades a verdict
  # rather than aborting a whole report. This class carries enough detail
  # for the report to explain *why* a probe was unusable.
  class NetworkError < Error
    KINDS = %i[dns connect tls timeout protocol redirect too_large uri budget].freeze

    attr_reader :kind, :uri

    def initialize(message, kind:, uri: nil)
      super(message)
      @kind = KINDS.include?(kind) ? kind : :protocol
      @uri  = uri
    end

    def self.from_exception(exception, uri: nil)
      case exception
      when OpenSSL::SSL::SSLError
        new(exception.message, kind: :tls, uri: uri)
      when Net::OpenTimeout, Net::ReadTimeout, Timeout::Error
        new(exception.message, kind: :timeout, uri: uri)
      when Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
           Errno::ECONNRESET, Errno::EPIPE
        new(exception.message, kind: :connect, uri: uri)
      when SocketError
        new(exception.message, kind: :dns, uri: uri)
      when URI::InvalidURIError
        new(exception.message, kind: :uri, uri: uri)
      else
        new("#{exception.class}: #{exception.message}", kind: :protocol, uri: uri)
      end
    end

    # Short, actionable hints. A scanner that only prints `getaddrinfo:
    # nodename nor servname provided` wastes the operator's time.
    def hint
      case kind
      when :dns
        "the hostname did not resolve — check spelling, DNS, or your resolver"
      when :connect
        "TCP connection failed — check the port, firewall, or whether the host is up"
      when :tls
        "TLS handshake failed — if this is an authorized self-signed origin, retry with --insecure"
      when :timeout
        "the request timed out — raise --timeout or try a closer vantage point"
      when :redirect
        "the redirect chain was rejected — inspect it with -v; only http(s) hops are followed"
      when :too_large
        "the response exceeded --max-body and was truncated"
      when :budget
        "the per-target request budget was exhausted — raise --max-requests if authorized"
      when :uri
        "the URL could not be parsed — pass a full http(s) URL or a bare hostname"
      else
        "the request failed at the protocol layer — retry with -v for the exact response"
      end
    end
  end

  # Raised when the per-target request budget is exhausted. Kept separate so
  # the scanner can stop cleanly instead of reporting a network failure.
  class BudgetExceeded < NetworkError
    def initialize(uri = nil)
      super("per-target request budget exhausted", kind: :budget, uri: uri)
    end
  end
end
