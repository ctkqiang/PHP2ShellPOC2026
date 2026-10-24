# frozen_string_literal: true

require "shellwords"

module PHP2ShellPOC2026
  # Concrete, copy-pasteable next steps. The tool catalogue says what
  # equipment exists; this says what to run next on this host. Every command
  # here is read-only (GET/HEAD, DNS, TLS) unless it is explicitly marked
  # authorized, and nothing in this file exploits anything.
  module NextActions
    Action = Struct.new(:label, :command, :why, :authorized, keyword_init: true) do
      def to_h
        { label: label, command: command, why: why, authorized: authorized }
      end
    end

    def self.for(verdict, environment, target, options)
      url  = target.uri.to_s
      host = target.ascii_host
      actions = []

      actions << action("Verify the response from your own egress",
                        "curl -sSI #{shell(url)}",
                        "Confirms the status line and headers without any scanner-specific User-Agent.")
      if target.scheme == "https"
        actions << action("Inspect the TLS certificate",
                          "openssl s_client -connect #{shell("#{host}:#{target.port}")} -servername #{shell(host)} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName",
                          "Certificate SANs and issuer are passive origin-discovery signals.")
      end
      actions << action("Resolve DNS",
                        "dig +short #{shell(host)}",
                        "Confirms where the hostname points and whether a CDN/origin split is visible.")

      case verdict.status
      when :inconclusive
        if verdict.reason_code == :blocked
          actions << action("Re-run from an approved proxy or egress (authorized)",
                            "php2shell-poc2026 --proxy http://127.0.0.1:8080 --profile deep #{shell(url)}",
                            "A different vantage point may see the application instead of the edge block. Do not use this to bypass a control without authorization.")
          actions << action("Read the PHP version host-side",
                            "php -v && (command -v dpkg >/dev/null && dpkg -l | grep -i php || true)",
                            "The authoritative answer when the edge denies external probes.")
        elsif verdict.reason_code == :rate_limited
          actions << action("Slow down and retry",
                            "php2shell-poc2026 --delay 2000 --threads 1 #{shell(url)}",
                            "A 429 is throttling, not absence; a slower pass may complete.")
        elsif verdict.reason_code == :soft_404
          actions << action("Read the version from a distinct path or host-side",
                            "php2shell-poc2026 --profile deep #{shell(url)}",
                            "Catch-all routing makes path status codes unreliable; deeper probes may hit a distinct response.")
        else
          actions << action("Widen the probe",
                            "php2shell-poc2026 --profile deep -v #{shell(url)}",
                            "More paths and a request trace may turn an inconclusive result into evidence.")
        end
      when :unknown
        actions << action("Widen the probe",
                          "php2shell-poc2026 --profile deep #{shell(url)}",
                          "Deep mode adds phpinfo candidates, framework paths and robots/sitemap-derived .php paths.")
        actions << action("Corroborate the stack",
                          "whatweb #{shell(url)}",
                          "A second passive fingerprint can reveal a version the headers hide.")
      when :no_php
        actions << action("Check other ports and vhosts (authorized)",
                          "nmap -sV -p 80,443,8080,8443 #{shell(host)}",
                          "PHP may live on a different port or Host header than the one tested.",
                          authorized: true)
        actions << action("Fingerprint sibling hosts",
                          "httpx -u #{shell(url)} -tech-detect",
                          "Confirms whether the no-PHP result is specific to this route or the whole host.")
      when :exposed
        actions << action("Emit a CI-ready SARIF report",
                          "php2shell-poc2026 --format sarif --output php2shell.sarif #{shell(url)}",
                          "Turns the finding into a machine-readable artifact for the security backlog.")
        actions << action("Inventory sibling hosts (authorized)",
                          "nuclei -u #{shell(url)} -t tech-detect",
                          "Find other hosts on the same branch before closing the finding.",
                          authorized: true)
      when :patched
        actions << action("Keep it patched in CI",
                          "php2shell-poc2026 --fail-on inconclusive #{shell(url)}",
                          "Exit 2 on exposure, exit 3 on a blocked/unverified result, so a silent edge block cannot masquerade as clean.")
      end

      actions << action("Enforce scope on the next run",
                        "php2shell-poc2026 --scope scope.txt --require-scope #{shell(url)}",
                        "Fails closed (exit 4) if the target is outside the authorized list.")
      actions
    end

    def self.action(label, command, why, authorized: false)
      Action.new(label: label, command: command, why: why, authorized: authorized)
    end

    def self.shell(value)
      Shellwords.escape(value.to_s)
    end
  end
end
