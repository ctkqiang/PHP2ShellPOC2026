# frozen_string_literal: true

require_relative "../sanitize"

module PHP2ShellPOC2026
  module Report
    # One row per target, for spreadsheets and asset inventories. The CSV is
    # deliberately flat: a SIEM or a spreadsheet wants a stable column set,
    # not a nested document. `--json`/`--ndjson` remain the formats for the
    # full evidence.
    module Csv
      COLUMNS = %w[
        target url verdict status reason_code risk_score risk_grade confidence
        version branch fix_floor access_state http_status server edge cdn waf sapi
        framework requests coverage_usable coverage_attempted hackable answer
        decision_action error
      ].freeze

      def self.render(results, _options, summary: nil, meta: {})
        lines = [COLUMNS.join(",")]
        results.each do |result|
          v = result.verdict
          e = result.environment
          coverage = result.fingerprint[:coverage] || {}
          row = [
            result.target.display,
            result.target.uri.to_s,
            v.label,
            v.status,
            v.reason_code,
            result.risk[:score],
            result.risk[:grade],
            v.confidence,
            v.version,
            v.branch,
            v.fix_floor,
            v.access&.state,
            result.probes.find { |probe| probe.purpose == "root" }&.status,
            e.server,
            e.edge,
            e.cdn,
            e.waf,
            e.sapi,
            v.attack_surface[:framework],
            result.meta[:requests] || result.fingerprint[:requests],
            coverage[:usable],
            coverage[:attempted],
            result.hackability.hackable?,
            result.hackability.answer,
            result.hackability.action,
            result.error
          ]
          lines << row.map { |value| Sanitize.csv(value) }.join(",")
        end
        lines.join("\n") + "\n"
      end
    end
  end
end
