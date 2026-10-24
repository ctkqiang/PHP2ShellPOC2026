# frozen_string_literal: true

require "json"

require_relative "../version"

module PHP2ShellPOC2026
  module Report
    # Machine-readable envelope. The schema is versioned separately from the
    # gem because CI pipelines pin it; adding fields is fine, removing or
    # renaming one requires a schema bump.
    module Json
      SCHEMA_VERSION = "3.0"

      def self.render(results, options, summary:, meta: {})
        payload = {
          schema_version: SCHEMA_VERSION,
          tool: { name: "php2shell-poc2026", version: VERSION, homepage: HOMEPAGE },
          generated_at: meta[:generated_at] || Time.now.utc.iso8601,
          options: options.public_h,
          summary: summary,
          results: results.each_with_object({}) do |result, acc|
            acc[result.target.display] = result.to_h(include_body: options.evidence)
          end
        }
        body = options.compact ? JSON.generate(payload) : JSON.pretty_generate(payload)
        body + "\n"
      end
    end
  end
end
