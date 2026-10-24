# frozen_string_literal: true

require "time"

require_relative "summary"
require_relative "report/text"
require_relative "report/json"
require_relative "report/markdown"
require_relative "report/sarif"
require_relative "report/csv"
require_relative "report/ndjson"

module PHP2ShellPOC2026
  # Rendering lives here rather than in the CLI so presentation can change —
  # or gain a seventh format — without touching scan logic. Every renderer
  # receives the same results and the same computed summary, which is how
  # text, JSON and SARIF stay numerically consistent.
  module Report
    FORMATS = %w[text json markdown sarif csv ndjson].freeze

    def self.render(results, options, meta: {})
      meta = meta.merge(
        generated_at: meta[:generated_at] || Time.now.utc.iso8601,
        profile: meta[:profile] || options.profile,
        format: options.format
      )
      summary = Summary.compute(results, meta: meta)

      case options.format
      when "text"
        Text.new(results, options, summary: summary, meta: meta).render
      when "json"
        Json.render(results, options, summary: summary, meta: meta)
      when "markdown"
        Markdown.render(results, options, summary: summary, meta: meta)
      when "sarif"
        Sarif.render(results, options, summary: summary, meta: meta)
      when "csv"
        Csv.render(results, options, summary: summary, meta: meta)
      when "ndjson"
        Ndjson.render(results, options, summary: summary, meta: meta)
      else
        raise UsageError, "unknown format: #{options.format.inspect}"
      end
    end

    def self.summary(results, options, meta: {})
      Summary.compute(results, meta: meta.merge(profile: options.profile, format: options.format))
    end
  end
end
