# frozen_string_literal: true

require "shellwords"
require_relative "i18n"

module PHP2ShellPOC2026
  # Concrete, copy-pasteable next steps. The tool catalogue says what
  # equipment exists; this says what to run next on this host. Every command
  # here is read-only (GET/HEAD, DNS, TLS) unless it is explicitly marked
  # authorized, and nothing in this file exploits anything.
  #
  # Priority is a display hint, not a security rating: 1 is the action that
  # actually resolves this verdict, 3 is corroborating recon, 4 is process.
  # The text report shows the top four unless -v asks for the whole list, so
  # a blocked host gets a short answer instead of a generic playbook.
  module NextActions
    Action = Struct.new(:label, :command, :why, :authorized, :priority, keyword_init: true) do
      def to_h
        { label: label, command: command, why: why, authorized: authorized }
      end
    end

    def self.for(verdict, environment, target, options)
      url  = target.uri.to_s
      host = target.ascii_host
      actions = []

      actions << action(t("data.actions.verify.label", "Verify the response from your own egress"),
                        "curl -sSI #{shell(url)}",
                        t("data.actions.verify.why",
                          "Confirms the status line and headers without any scanner-specific User-Agent."),
                        priority: 1)

      case verdict.status
      when :inconclusive
        if verdict.reason_code == :blocked
          unless options.browser_ua
            actions << action(t("data.actions.browser_ua.label",
                                "Retry with a browser-compatible User-Agent (authorized)"),
                              "php2shell-poc2026 --browser-ua --profile deep #{shell(url)}",
                              t("data.actions.browser_ua.why",
                                "The edge is rejecting the scanner's identifying User-Agent. A browser-compatible " \
                                "UA may reach the application instead of the block page. Use it only when your " \
                                "authorization permits it."),
                              authorized: true, priority: 1)
          end
          actions << action(t("data.actions.blocked_retry.label",
                              "Re-run from an approved proxy or egress (authorized)"),
                            "php2shell-poc2026 --proxy http://127.0.0.1:8080 --profile deep #{shell(url)}",
                            t("data.actions.blocked_retry.why",
                              "A different vantage point may see the application instead of the edge block. Do not " \
                              "use this to bypass a control without authorization."),
                            priority: 1)
          actions << action(t("data.actions.host_version.label", "Read the PHP version host-side"),
                            "php -v && (command -v dpkg >/dev/null && dpkg -l | grep -i php || true)",
                            t("data.actions.host_version.why",
                              "The authoritative answer when the edge denies external probes."),
                            priority: 1)
        elsif verdict.reason_code == :rate_limited
          actions << action(t("data.actions.slow_down.label", "Slow down and retry"),
                            "php2shell-poc2026 --delay 2000 --threads 1 #{shell(url)}",
                            t("data.actions.slow_down.why",
                              "A 429 is throttling, not absence; a slower pass may complete."),
                            priority: 1)
        elsif verdict.reason_code == :soft_404
          actions << action(t("data.actions.distinct_path.label",
                              "Read the version from a distinct path or host-side"),
                            "php2shell-poc2026 --profile deep #{shell(url)}",
                            t("data.actions.distinct_path.why",
                              "Catch-all routing makes path status codes unreliable; deeper probes may hit a " \
                              "distinct response."),
                            priority: 1)
        else
          actions << action(t("data.actions.widen.label", "Widen the probe"),
                            "php2shell-poc2026 --profile deep -v #{shell(url)}",
                            t("data.actions.widen.why",
                              "More paths and a request trace may turn an inconclusive result into evidence."),
                            priority: 1)
        end
      when :unknown
        actions << action(t("data.actions.widen.label", "Widen the probe"),
                          "php2shell-poc2026 --profile deep #{shell(url)}",
                          t("data.actions.deep_why",
                            "Deep mode adds phpinfo candidates, framework paths and robots/sitemap-derived .php paths."),
                          priority: 1)
        actions << action(t("data.actions.corroborate.label", "Corroborate the stack"),
                          "whatweb #{shell(url)}",
                          t("data.actions.corroborate.why",
                            "A second passive fingerprint can reveal a version the headers hide."),
                          priority: 2)
      when :no_php
        actions << action(t("data.actions.other_ports.label", "Check other ports and vhosts (authorized)"),
                          "nmap -sV -p 80,443,8080,8443 #{shell(host)}",
                          t("data.actions.other_ports.why",
                            "PHP may live on a different port or Host header than the one tested."),
                          authorized: true, priority: 2)
        actions << action(t("data.actions.siblings.label", "Fingerprint sibling hosts"),
                          "httpx -u #{shell(url)} -tech-detect",
                          t("data.actions.siblings.why",
                            "Confirms whether the no-PHP result is specific to this route or the whole host."),
                          priority: 2)
      when :vulnerable, :eol
        actions << action(t("data.actions.rescan_after_fix.label", "Re-scan after the upgrade"),
                          "php2shell-poc2026 #{shell(url)}",
                          t("data.actions.rescan_after_fix.why",
                            "Confirms the exposed host now reports a fixed PHP version."),
                          priority: 1)
        actions << action(t("data.actions.sarif.label", "Emit a CI-ready SARIF report"),
                          "php2shell-poc2026 --format sarif --output php2shell.sarif #{shell(url)}",
                          t("data.actions.sarif.why",
                            "Turns the finding into a machine-readable artifact for the security backlog."),
                          priority: 2)
        actions << action(t("data.actions.inventory.label", "Inventory sibling hosts (authorized)"),
                          "nuclei -u #{shell(url)} -t tech-detect",
                          t("data.actions.inventory.why",
                            "Find other hosts on the same branch before closing the finding."),
                          authorized: true, priority: 2)
      when :patched
        actions << action(t("data.actions.rescan_after_update.label", "Re-scan after the next PHP update"),
                          "php2shell-poc2026 #{shell(url)}",
                          t("data.actions.rescan_after_update.why",
                            "Confirms the host is still on a fixed release after the update cycle."),
                          priority: 1)
        actions << action(t("data.actions.ci.label", "Keep it patched in CI"),
                          "php2shell-poc2026 --fail-on inconclusive #{shell(url)}",
                          t("data.actions.ci.why",
                            "Exit 2 on exposure, exit 3 on a blocked/unverified result, so a silent edge block " \
                            "cannot masquerade as clean."),
                          priority: 2)
      end

      if target.scheme == "https"
        actions << action(t("data.actions.tls.label", "Inspect the TLS certificate"),
                          "openssl s_client -connect #{shell("#{host}:#{target.port}")} " \
                          "-servername #{shell(host)} </dev/null 2>/dev/null | " \
                          "openssl x509 -noout -subject -issuer -dates -ext subjectAltName",
                          t("data.actions.tls.why",
                            "Certificate SANs and issuer are passive origin-discovery signals."),
                          priority: 3)
      end
      actions << action(t("data.actions.dns.label", "Resolve DNS"),
                        "dig +short #{shell(host)}",
                        t("data.actions.dns.why",
                          "Confirms where the hostname points and whether a CDN/origin split is visible."),
                        priority: 3)

      actions << action(t("data.actions.scope.label", "Enforce scope on the next run"),
                        "php2shell-poc2026 --scope scope.txt --require-scope #{shell(url)}",
                        t("data.actions.scope.why",
                          "Fails closed (exit 4) if the target is outside the authorized list."),
                        priority: 4)

      actions.each_with_index.sort_by { |action, index| [action.priority, index] }
             .map(&:first)
    end

    def self.action(label, command, why, authorized: false, priority: 2)
      Action.new(label: label, command: command, why: why, authorized: authorized,
                 priority: priority)
    end

    def self.shell(value)
      Shellwords.escape(value.to_s)
    end

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end
    private_class_method :t
  end
end
