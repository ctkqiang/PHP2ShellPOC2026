# frozen_string_literal: true

require_relative "i18n"

module PHP2ShellPOC2026
  # What to actually do about the finding. Each verdict gets the steps that
  # follow from it, written to be pasted straight into a ticket: version
  # numbers specific to this host, the config keys to change, and the honest
  # distinction between a fix and a compensation.
  module Remediation
    def self.for(verdict, environment)
      case verdict.status
      when :vulnerable then vulnerable(verdict, environment)
      when :eol        then eol(verdict, environment)
      when :patched    then patched(verdict)
      when :no_php     then no_php(verdict)
      when :unknown    then unknown(verdict)
      else                  inconclusive(verdict, environment)
      end
    end

    def self.vulnerable(verdict, environment)
      branch = verdict.branch
      floor  = verdict.fix_floor

      steps = [
        t("data.remediation.vulnerable.upgrade",
          "Upgrade PHP %{version} to at least %{floor} — the first release on branch %{branch} " \
          "carrying the fix. If your distro package lags upstream, apply the vendor backport and record " \
          "which advisory it maps to.",
          version: verdict.version, floor: floor, branch: branch),
        t("data.remediation.vulnerable.waf",
          "Interim: deploy the WAF rules listed in this report — block PHP_SESSION_UPLOAD_PROGRESS in POST " \
          "bodies, enforce decoded body-size / part-count / nesting limits. They cover both arms of the bug " \
          "without touching application code."),
        t("data.remediation.vulnerable.harden",
          "Harden the host: session.upload_progress.enabled=Off, a fixed php_admin_value memory_limit clients " \
          "cannot override, low post_max_size. Restart every FPM/Apache worker afterwards."),
        t("data.remediation.vulnerable.verify",
          "Verify the effective config from a live web request (phpinfo), not the CLI — FPM and CLI routinely " \
          "read different php.ini files, and the CLI answer is the wrong one.")
      ]
      steps.concat(edge_steps(environment))
      steps
    end

    # No fix exists on this branch, so the list is honest about what is a
    # migration and what is only compensation.
    def self.eol(verdict, environment)
      steps = [
        t("data.remediation.eol.migrate",
          "PHP %{version} (branch %{branch}) has no fixed release — plan a migration to a " \
          "supported branch (8.4 or 8.5). Everything below is compensation, not a fix.",
          version: verdict.version, branch: verdict.branch),
        t("data.remediation.eol.backport",
          "If migration cannot start now: apply the distro/vendor backport for 7.4/8.0/8.1 where it exists, " \
          "and note the advisory it tracks so the exception has an expiry date."),
        t("data.remediation.eol.edge",
          "Compensate at the edge meanwhile — the WAF rules listed in this report, plus origin locking so a " \
          "leaked direct IP cannot bypass them."),
        t("data.remediation.eol.sweep",
          "EOL interpreters cluster on forgotten hosts: sweep subdomains, vhosts and staging boxes for the same " \
          "branch before closing the finding.")
      ]
      steps.concat(edge_steps(environment))
      steps
    end

    def self.patched(verdict)
      [
        t("data.remediation.patched.none",
          "No action for this bug class: %{version} meets the branch fix level (%{floor}).",
          version: verdict.version, floor: verdict.fix_floor),
        t("data.remediation.patched.updates",
          "Keep the branch on security updates — this verdict flips back to vulnerable on a downgrade or a " \
          "stale base image, both of which happen more often than anyone plans for."),
        t("data.remediation.patched.rerun",
          "Re-run this tool after upgrades or migrations: exit 2 means exposed, and --fail-on inconclusive " \
          "makes a blocked or unverified result fail CI too.")
      ]
    end

    def self.no_php(_verdict)
      [
        t("data.remediation.no_php.routes",
          "No PHP action on the tested routes: the control path behaved normally and no PHP markers were " \
          "observed. Keep the result scoped to those routes."),
        t("data.remediation.no_php.routing",
          "If this host is supposed to run PHP, check vhost routing, rewrites and alternate ports — a static " \
          "response can hide a PHP backend behind a different Host header."),
        t("data.remediation.no_php.siblings",
          "Repeat the check against sibling subdomains and staging hosts; PHP presence is rarely uniform across " \
          "an estate."),
        t("data.remediation.no_php.config",
          "Config-audit steps in this report are still worth verifying on any PHP host you do find.")
      ]
    end

    def self.unknown(verdict)
      steps = case verdict.reason_code
              when :branch_only
                [
                  t("data.remediation.unknown.branch_only",
                    "Only a branch-level version (%{version}) was exposed. Read the exact patch level " \
                    "host-side (php -v, your package manager, or a protected phpinfo page) and compare against " \
                    "%{floor}.",
                    version: verdict.version, floor: verdict.fix_floor || "the branch fix level")
                ]
              when :newer_than_table
                [
                  t("data.remediation.unknown.newer_than_table",
                    "The observed version (%{version}) is newer than this tool's fix table. Check the " \
                    "current PHP release notes and your vendor advisory before treating it as safe.",
                    version: verdict.version)
                ]
              else
                [
                  t("data.remediation.unknown.version",
                    "Establish the interpreter version: read it host-side (package manager), expose phpinfo " \
                    "behind access control briefly, or re-run with --profile deep."),
                  t("data.remediation.unknown.header",
                    "If X-Powered-By was stripped deliberately, header hygiene is not patch hygiene — verify the " \
                    "branch from the host.")
                ]
              end

      steps + [
        t("data.remediation.unknown.unversioned",
          "Do not treat an unversioned response as patched. The parser-level bug can still be present."),
        t("data.remediation.unknown.config",
          "The config-audit checks in this report apply to any PHP host: verify them regardless of what the " \
          "version turns out to be.")
      ]
    end

    def self.inconclusive(verdict, environment)
      steps = case verdict.reason_code
              when :blocked
                [
                  t("data.remediation.inconclusive.blocked.not_evidence",
                    "The edge denied every probe, including a random control path. This is not evidence that PHP " \
                    "is absent or patched — re-check scope/ROE and confirm the block is intentional."),
                  t("data.remediation.inconclusive.blocked.retry",
                    "If authorized, retry from an approved egress or through the program's proxy, or ask the host " \
                    "owner for a host-side version read. Do not attempt to bypass the control."),
                  t("data.remediation.inconclusive.blocked.origin",
                    "Check whether the origin is reachable directly outside the edge; a 403 at the CDN says nothing " \
                    "about the origin's patch level."),
                  t("data.remediation.inconclusive.blocked.logs",
                    "Review edge logs for the canary-path requests from this scan; treat them as reconnaissance.")
                ]
              when :restricted
                [
                  t("data.remediation.inconclusive.restricted.verify",
                    "The root path is protected while a control path resolved. Verify the interpreter host-side or " \
                    "against another route on the same vhost."),
                  t("data.remediation.inconclusive.restricted.auth",
                    "If authenticated testing is authorized, assess the authenticated surface separately; do not " \
                    "assume the login protects the parser — it runs before application auth.")
                ]
              when :auth_wall
                [
                  t("data.remediation.inconclusive.auth_wall.version",
                    "The site is behind a login. Read the PHP version host-side or from a protected diagnostic " \
                    "page; authenticated testing requires separate authorization."),
                  t("data.remediation.inconclusive.auth_wall.parser",
                    "Remember that this bug class fires during request parsing, before authentication code runs: " \
                    "a login wall does not by itself close it.")
                ]
              when :rate_limited
                [
                  t("data.remediation.inconclusive.rate_limited.backoff",
                    "The origin returned HTTP 429. Raise --delay, lower --threads, and retry later; a 429 is not " \
                    "evidence of absence."),
                  t("data.remediation.inconclusive.rate_limited.coordinate",
                    "If the program publishes rate limits, stay well below them and coordinate with the target's " \
                    "SOC for high-volume work.")
                ]
              when :soft_404
                [
                  t("data.remediation.inconclusive.soft_404.status_codes",
                    "The server returns 200 for nonexistent paths. Do not trust path status codes or directory " \
                    "brute-force results on this host; use header, cookie and body differentials."),
                  t("data.remediation.inconclusive.soft_404.version",
                    "Establish the interpreter version host-side or from a path with a distinct response.")
                ]
              when :unreachable
                [
                  t("data.remediation.inconclusive.unreachable.retry",
                    "No usable response was received. Check DNS, TCP reachability, TLS and the timeout; retry from " \
                    "an approved vantage point."),
                  t("data.remediation.inconclusive.unreachable.insecure",
                    "Use --insecure only for an authorized self-signed origin, and only after confirming the host.")
                ]
              when :server_error
                [
                  t("data.remediation.inconclusive.server_error.logs",
                    "The origin returned 5xx on every probe. Retry later and check the host's error logs; an " \
                    "unhealthy app is not a patched app."),
                  t("data.remediation.inconclusive.server_error.owner",
                    "If the 5xx is persistent, coordinate with the host owner before drawing any exposure conclusion.")
                ]
              else
                [
                  t("data.remediation.inconclusive.other",
                    "The scan could not produce usable application evidence. Retry with -v, a different profile, " \
                    "or a host-side version read.")
                ]
              end

      if verdict.reason_code == :blocked && environment.block_page
        block_page = environment.block_page
        steps.unshift(t("data.remediation.inconclusive.blocked.block_page",
                        "The edge returned a %{vendor} block page (%{summary}). This is bot/edge protection, not " \
                        "a patch verdict. If authorized, retry with --browser-ua or from an approved egress, or " \
                        "ask the host owner for a host-side version read.",
                        vendor: block_page.vendor || "edge",
                        summary: block_page.summary))
      end

      steps.concat(edge_steps(environment))
      steps
    end

    # Edge-dependent advice is shared: a CDN fronting an unpatched host and
    # a WAF that exists but may not cover this bug are both common enough to
    # be worth saying every time they are true.
    def self.edge_steps(environment)
      steps = []
      if environment.cdn?
        steps << t("data.remediation.edge.cdn",
                   "Lock the origin to the CDN range (%{cdn}) so the rules above cannot be sidestepped " \
                   "through a leaked direct IP — certificate transparency and old DNS will find it eventually.",
                   cdn: environment.cdn)
      end
      if environment.waf && environment.waf != "unidentified edge control" && environment.waf != "rate limiter"
        steps << t("data.remediation.edge.waf",
                   "Confirm the WAF (%{waf}) actually runs the PHP managed rule set at the version " \
                   "covering this CVE — presence of a WAF is not coverage of a rule.",
                   waf: environment.waf)
      end
      steps
    end

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end
    private_class_method :t
  end
end
