# frozen_string_literal: true

require "json"

module PHP2ShellPOC2026
  # Rendering lives here rather than in the CLI so that presentation can
  # change — or gain a third format — without touching scan logic.
  #
  # Every line the text renderer prints is measured against the terminal
  # width through Layout: the run opens with a summary table (stacked
  # instead of tabulated when the terminal is too narrow to hold columns),
  # long prose wraps with hanging indents, and identifier-style lines
  # truncate rather than wrap. One report, readable on a phone and on a
  # ultrawide, no reader fighting soft wraps.
  module Report
    SEVERITY = { vulnerable: "CRITICAL", eol: "CRITICAL", patched: "OK", unknown: "INFO" }.freeze

    VERDICT_CODE = { vulnerable: "VULN", eol: "EOL", patched: "PATCH", unknown: "UNK" }.freeze
    HACK_MARK    = { hackable: "YES", likely: "YES", uncertain: "?", not_hackable: "NO" }.freeze
    GRADE_CODE   = {
      "CRITICAL" => "CRIT", "HIGH" => "HIGH", "MEDIUM" => "MED",
      "LOW" => "LOW", "NONE" => "NONE"
    }.freeze

    def self.json(results)
      JSON.pretty_generate(results.transform_values(&:to_h))
    end

    class Text
      def initialize(results, redteam: false, toolchain: false, verbose: false)
        @results   = results
        @redteam   = redteam
        @toolchain = toolchain
        @verbose   = verbose
      end

      def render
        summary_table
        @results.each do |target, result|
          puts Layout.truncate(target, Layout.width)
          summary(result)
          attack_chain(result)
          detections(result)
          red_team(result) if @redteam
          toolchain(result) if @toolchain
          trace(result) if @verbose
          technical_summary(result)
          remediation(result)
          puts
        end
        run_summary
        tip
      end

      private

      # -- overview ---------------------------------------------------------

      # The first thing on screen: one row per target, columns sized to the
      # terminal. Stacked rows come out of Layout on narrow screens, so a
      # phone gets the same information in a different shape, not a table
      # somebody has to scroll sideways to read.
      def summary_table
        rows = @results.map do |target, r|
          [target.to_s,
           VERDICT_CODE.fetch(r.verdict.status, "???"),
           "#{r.risk[:score]} #{GRADE_CODE.fetch(r.risk[:grade].to_s, '?')}",
           HACK_MARK.fetch(r.hackability.rating, "?"),
           format("%.2f", r.hackability.ratio)]
        end

        Layout.table(%w[TARGET VERDICT RISK HACK RATIO], rows).each { |line| puts line }
        puts
      end

      # -- per-target -------------------------------------------------------

      def summary(result)
        v = result.verdict
        e = result.environment
        s = v.attack_surface
        fp = result.fingerprint

        field("verdict", "#{SEVERITY.fetch(v.status, 'INFO')} (#{v.status})   " \
                         "risk #{result.risk[:score]}/10 (#{result.risk[:grade]})")
        field("version", "#{v.version || 'unknown'}" \
                         "#{v.version_source ? "   (source: #{v.version_source})" : ''}")
        field("reason", v.reason)
        field("surface", "php=#{s[:php_detected]} phpinfo=#{s[:phpinfo_exposed]} " \
                         "upload_progress=#{s[:upload_progress]} php_errors=#{s[:php_errors]}")
        field("env", "server=#{e.server || 'n/a'} cdn=#{e.cdn || 'none'} " \
                     "waf=#{e.waf || 'none'} sapi=#{e.sapi}")
        block(4, e.sapi_rationale) if e.sapi_rationale
        field("observed", "x-powered-by=#{fp[:x_powered_by] || 'absent'} " \
                          "server=#{fp[:server] || 'absent'} " \
                          "cookies=#{fp[:cookie_names].empty? ? 'none' : fp[:cookie_names].join(',')} " \
                          "statuses=#{fp[:statuses].join(',')} paths=#{fp[:probed_paths].join(',')}")
      end

      def attack_chain(result)
        if result.attack_chain.empty?
          puts "\n  ATT&CK  : no chain mapped without a confirmed vulnerable version"
          return
        end

        puts "\n  ATT&CK kill chain:"
        result.attack_chain.each do |t|
          puts Layout.truncate("    #{t[:id].ljust(9)} #{t[:tactic].ljust(22)} #{t[:name]}", Layout.width)
        end
        puts
        result.attack_chain.each { |t| hung("    - #{t[:id]}: ", t[:note]) }
      end

      def detections(result)
        puts "\n  Detection opportunities:"
        result.detections.each do |d|
          hung("    [#{d[:layer]}] ", d[:control])
          hung("        ", d[:detail])
        end
      end

      def red_team(result)
        return if result.red_team.empty?

        puts "\n  Red team perspective:"
        result.red_team.each { |n| hung("    * ", n) }
      end

      # Grouped by phase so the catalogue reads in engagement order rather
      # than as one undifferentiated wall of tools.
      def toolchain(result)
        puts "\n  Standard toolchain:"
        result.tooling.group_by(&:phase).each do |phase, entries|
          puts "    #{phase}:"
          entries.each do |e|
            hung("      ", e.tool)
            hung("          purpose:   ", e.purpose)
            hung("          relevance: ", e.relevance)
            unless e.techniques.empty?
              hung("          ATT&CK:    ", e.techniques.join(", "))
            end
          end
        end
      end

      def trace(result)
        return if result.trace.empty?

        puts "\n  Trace:"
        result.trace.each { |line| block(4, line) }
      end

      # -- the tail ---------------------------------------------------------

      # The evidence-weighed answer to "can this be hacked, right now, by
      # this bug class" — ratio, every signal that moved it, the
      # prerequisites, and what winning looks like. Positives print first,
      # heaviest contribution at the top.
      def technical_summary(result)
        h = result.hackability
        puts "\n  Technical summary (evidence-weighted):"
        field("hackability", "#{h.label}   positivity ratio #{format('%.2f', h.ratio)}  " \
                             "(positive #{h.positive} / negative #{h.negative})")
        puts "  signals     :"
        ordered_signals(h.signals).each do |s|
          sign = s.direction == :positive ? "+" : "-"
          hung("      #{sign}#{s.weight}  ", s.label)
        end
        puts "  prerequisites:"
        h.prerequisites.each { |p| hung("      - ", p) }
        field("reliability", h.reliability)
        field("impact", h.impact)
      end

      def ordered_signals(signals)
        signals.sort_by { |s| [s.direction == :positive ? 0 : 1, -s.weight] }
      end

      # The helpful part: what to do about it, ordered, with version numbers
      # this host can act on. Printed last per target so the report ends on
      # an action rather than an observation.
      def remediation(result)
        return if result.remediation.empty?

        puts "  Remediation (what to do next):"
        result.remediation.each { |step| hung("      - ", step) }
      end

      # Cross-target tail: how many targets are hackable, and how positive
      # the evidence is across the batch — the line that gets pasted into
      # a ticket.
      def run_summary
        ratings  = @results.values.map(&:hackability)
        return if ratings.empty?

        hackable  = ratings.count(&:hackable?)
        uncertain = ratings.count { |h| h.rating == :uncertain }
        negative  = ratings.size - hackable - uncertain
        pos       = ratings.sum(&:positive)
        neg       = ratings.sum(&:negative)
        total     = pos + neg

        puts "  Run summary"
        field("targets", "#{ratings.size}   hackable: #{hackable}   " \
                         "inconclusive: #{uncertain}   not hackable: #{negative}", 4)
        field("positivity", "#{format('%.2f', hackable.to_f / ratings.size)} of targets flagged hackable " \
                            "(#{hackable}/#{ratings.size})   " \
                            "aggregate signal ratio #{format('%.2f', total.zero? ? 0.0 : pos.to_f / total)}", 4)
      end

      def tip
        puts
        hung("  Tip: ", "add -r for red-team notes, -c for the full toolchain catalogue, -v for a request " \
                        "trace, --json for the machine-readable report. Set COLUMNS to force the report " \
                        "width. Exit codes: 0 clear, 1 usage error, 2 exposed.")
      end

      # -- line helpers -----------------------------------------------------

      # "  label : value", wrapped to the terminal with continuations
      # aligned under the value rather than the label.
      def field(label, value, indent = 2)
        prefix = "#{' ' * indent}#{label.ljust(8)} : "
        Layout.wrap(value, Layout.width - prefix.length).each_with_index do |line, i|
          puts((i.zero? ? prefix : " " * prefix.length) + line)
        end
      end

      # Marker-prefixed line ("- ", "+3  ", "[WAF] ") that wraps with
      # continuations hung past the marker. Prefix travels separately so
      # Layout never has to guess where the marker ends.
      def hung(prefix, text)
        Layout.wrap_hanging(prefix, text).each_with_index do |line, i|
          puts((i.zero? ? "" : " " * prefix.length) + line)
        end
      end

      # Plain indented paragraph (rationales, trace lines).
      def block(indent, text)
        Layout.wrap(text, Layout.width - indent).each { |line| puts(" " * indent + line) }
      end
    end
  end
end
