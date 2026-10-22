# frozen_string_literal: true

module PHP2ShellPOC2026
  # What to actually do about the finding. Each verdict gets the steps that
  # follow from it, written to be pasted straight into a ticket: version
  # numbers specific to this host, the config keys to change, and the
  # honest distinction between a fix and a compensation.
  #
  # Keep the tone of an engineer who has shipped this upgrade before —
  # concrete, ordered, no "consider reviewing". If a step cannot be acted
  # on as written, it does not belong here.
  module Remediation
    def self.for(verdict, environment)
      case verdict.status
      when :vulnerable then vulnerable(verdict, environment)
      when :eol        then eol(verdict, environment)
      when :patched    then patched(verdict)
      else                  unconfirmed
      end
    end

    def self.vulnerable(verdict, environment)
      branch = branch_of(verdict)
      floor  = Verdict::FIXED_RELEASES[branch]

      steps = [
        "Upgrade PHP #{verdict.version} to at least #{floor} — the first release on branch #{branch} " \
        "carrying the fix. If your distro package lags upstream, apply the vendor backport and record " \
        "which advisory it maps to.",
        "Interim: deploy the WAF rules listed in this report — block PHP_SESSION_UPLOAD_PROGRESS in POST " \
        "bodies, enforce decoded body-size / part-count / nesting limits. They cover both arms of the bug " \
        "without touching application code.",
        "Harden the host: session.upload_progress.enabled=Off, a fixed php_admin_value memory_limit clients " \
        "cannot override, low post_max_size. Restart every FPM/Apache worker afterwards.",
        "Verify the effective config from a live web request (phpinfo), not the CLI — FPM and CLI routinely " \
        "read different php.ini files, and the CLI answer is the wrong one."
      ]
      steps.concat(edge_steps(environment))
      steps
    end

    # No fix exists on this branch, so the list is honest about what is a
    # migration and what is only compensation.
    def self.eol(verdict, environment)
      steps = [
        "PHP #{verdict.version} (branch #{branch_of(verdict)}) has no fixed release — plan a migration to a " \
        "supported branch (8.4 or 8.5). Everything below is compensation, not a fix.",
        "If migration cannot start now: apply the distro/vendor backport for 7.4/8.0/8.1 where it exists, " \
        "and note the advisory it tracks so the exception has an expiry date.",
        "Compensate at the edge meanwhile — the WAF rules listed in this report, plus origin locking so a " \
        "leaked direct IP cannot bypass them.",
        "EOL interpreters cluster on forgotten hosts: sweep subdomains, vhosts and staging boxes for the same " \
        "branch before closing the finding."
      ]
      steps.concat(edge_steps(environment))
      steps
    end

    def self.patched(verdict)
      floor = Verdict::FIXED_RELEASES[branch_of(verdict)]

      [
        "No action for this bug class: #{verdict.version} meets the branch fix level (#{floor}).",
        "Keep the branch on security updates — this verdict flips back to vulnerable on a downgrade or a " \
        "stale base image, both of which happen more often than anyone plans for.",
        "Re-run this tool after upgrades or migrations: exit 0 is clear, exit 2 is exposed, so it drops " \
        "straight into CI."
      ]
    end

    def self.unconfirmed
      [
        "Establish the interpreter version first: read it host-side (package manager), expose phpinfo behind " \
        "access control briefly, or re-run with --deep.",
        "If X-Powered-By was stripped deliberately, treat exposure as unmanaged until a host-side read " \
        "confirms the branch — header hygiene is not patch hygiene.",
        "The config-audit checks in this report apply to any PHP host: verify them regardless of what the " \
        "version turns out to be."
      ]
    end

    # Edge-dependent advice is shared: a CDN fronting an unpatched host and
    # a WAF that exists but may not cover this bug are both common enough to
    # be worth saying every time they are true.
    def self.edge_steps(environment)
      steps = []
      steps << "Lock the origin to the CDN range (#{environment.cdn}) so the rules above cannot be sidestepped " \
               "through a leaked direct IP — certificate transparency and old DNS will find it eventually." if environment.cdn?
      steps << "Confirm the WAF (#{environment.waf}) actually runs the PHP managed rule set at the version " \
               "covering this CVE — presence of a WAF is not coverage of a rule." if environment.waf
      steps
    end

    def self.branch_of(verdict)
      verdict.version && verdict.version.segments[0, 2].join(".")
    end
  end
end
