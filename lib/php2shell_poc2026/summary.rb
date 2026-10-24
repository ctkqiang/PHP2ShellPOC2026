# frozen_string_literal: true

require_relative "version"

module PHP2ShellPOC2026
  # One summary shape for every output format. Text, JSON, Markdown and
  # SARIF should never disagree about how many targets were exposed.
  module Summary
    def self.compute(results, meta: {})
      counts = Hash.new(0)
      results.each { |result| counts[result.verdict.status] += 1 }

      attempted = results.sum { |result| result.fingerprint.dig(:coverage, :attempted).to_i }
      usable    = results.sum { |result| result.fingerprint.dig(:coverage, :usable).to_i }
      requests  = results.sum { |result| result.meta[:requests].to_i }
      duration  = results.sum { |result| result.meta[:duration_ms].to_f }

      exposed     = counts[:vulnerable] + counts[:eol]
      patched     = counts[:patched]
      no_php      = counts[:no_php]
      unverified  = counts[:unknown] + counts[:inconclusive]
      assessable  = exposed + patched + no_php
      errors      = results.count { |result| result.error }

      # The decision counts are authoritative for the report's yes/no/unknown
      # answer. They are normally equal to exposed/patched+no_php/unverified,
      # but keeping them separate means the summary cannot disagree with the
      # per-target DECISION cards if the evidence model changes.
      hackable          = results.count { |result| result.hackability.answer == :yes }
      not_hackable      = results.count { |result| result.hackability.answer == :no }
      decision_unknown  = results.count { |result| result.hackability.answer == :unknown }

      {
        total: results.size,
        exposed: exposed,
        vulnerable: counts[:vulnerable],
        eol: counts[:eol],
        patched: patched,
        no_php: no_php,
        unverified: unverified,
        hackable: hackable,
        not_hackable: not_hackable,
        decision_unknown: decision_unknown,
        unknown: counts[:unknown],
        inconclusive: counts[:inconclusive],
        errors: errors,
        assessable: assessable,
        blocked: results.count { |result| result.verdict.reason_code == :blocked },
        auth_wall: results.count { |result| result.verdict.reason_code == :auth_wall },
        rate_limited: results.count { |result| result.verdict.reason_code == :rate_limited },
        soft_404: results.count { |result| result.verdict.reason_code == :soft_404 },
        unreachable: results.count { |result| result.verdict.reason_code == :unreachable },
        coverage: {
          attempted: attempted,
          usable: usable,
          percent: attempted.zero? ? 0.0 : (usable.to_f / attempted * 100.0).round(1)
        },
        requests: requests,
        duration_ms: duration.round(1),
        scope_skipped: meta[:scope_skipped].to_i,
        generated_at: meta[:generated_at],
        tool: { name: "php2shell-poc2026", version: VERSION },
        profile: meta[:profile],
        format: meta[:format]
      }
    end
  end
end
