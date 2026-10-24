# frozen_string_literal: true

require "json"

module PHP2ShellPOC2026
  module Report
    # Newline-delimited JSON: one target record per line, then a run record.
    # This is the format to pipe into a log shipper; a multi-megabyte
    # pretty-printed document is not.
    module Ndjson
      def self.render(results, options, summary:, meta: {})
        lines = results.map do |result|
          JSON.generate(
            record_type: "target",
            generated_at: meta[:generated_at],
            result: result.to_h(include_body: options.evidence)
          )
        end
        lines << JSON.generate(record_type: "run", generated_at: meta[:generated_at], summary: summary)
        lines.join("\n") + "\n"
      end
    end
  end
end
