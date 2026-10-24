# frozen_string_literal: true

require_relative "../risk"
require_relative "../sanitize"

module PHP2ShellPOC2026
  module Report
    # Markdown is the format that gets pasted into a ticket or a bug bounty
    # submission. It is intentionally plain: headings, tables, checkboxes,
    # no HTML beyond <details> for the trace.
    module Markdown
      def self.render(results, options, summary:, meta: {})
        lines = []
        lines << "# php2shell-poc2026 report"
        lines << ""
        lines << "- **Tool:** php2shell-poc2026 #{VERSION}"
        lines << "- **Generated:** #{meta[:generated_at] || Time.now.utc.iso8601}"
        lines << "- **Profile:** #{options.profile}"
        lines << "- **Targets:** #{summary[:total]} (exposed #{summary[:exposed]}, patched #{summary[:patched]}, " \
                 "no PHP #{summary[:no_php]}, unverified #{summary[:unverified]})"
        lines << "- **Coverage:** #{summary[:coverage][:usable]}/#{summary[:coverage][:attempted]} probes usable"
        lines << ""
        lines << "> Authorized assessments only. This tool sends ordinary GET requests; it does not exploit anything."
        lines << ""

        lines << "## Summary"
        lines << ""
        lines << "| Target | Verdict | Risk | Hackability | Evidence |"
        lines << "|---|---|---|---|---|"
        results.each do |result|
          lines << "| #{cell(result.target.display)} | #{cell(result.verdict.label)} | #{cell(risk_text(result))} | " \
                   "#{cell(result.hackability.label)} | #{evidence_cell(result)} |"
        end
        lines << ""

        results.each { |result| target_section(lines, result, options) }

        lines << "## Run summary"
        lines << ""
        lines << "- Exposed: #{summary[:exposed]} (vulnerable #{summary[:vulnerable]}, end-of-life #{summary[:eol]})"
        lines << "- Patched: #{summary[:patched]}"
        lines << "- No PHP observed: #{summary[:no_php]}"
        lines << "- Unverified: #{summary[:unverified]} (blocked #{summary[:blocked]}, auth wall #{summary[:auth_wall]}, " \
                 "rate limited #{summary[:rate_limited]}, soft-404 #{summary[:soft_404]}, " \
                 "unreachable #{summary[:unreachable]}, unknown version #{summary[:unknown]})"
        lines << "- Requests: #{summary[:requests]} in #{format('%.1f', summary[:duration_ms] / 1000.0)} s"
        lines << "- Scope-skipped targets: #{summary[:scope_skipped]}" if summary[:scope_skipped].positive?
        lines << ""
        lines.join("\n") + "\n"
      end

      def self.target_section(lines, result, options)
        v = result.verdict
        e = result.environment
        h = result.hackability

        lines << "## #{result.target.display}"
        lines << ""
        lines << "**Verdict:** #{v.label} (`#{v.status}`) · **Risk:** #{risk_text(result)} · " \
                 "**Confidence:** #{v.confidence} · **Hackability:** #{h.label}"
        lines << ""
        lines << "- **Version:** #{v.version || 'unknown'}#{v.version_source ? " (source: #{v.version_source})" : ''}"
        lines << "- **Reason:** #{v.reason}"
        lines << "- **Access:** #{v.access ? "#{v.access.state} — #{v.access.reason}" : 'unknown'}"
        lines << "- **Environment:** server #{e.server || 'n/a'}, edge #{e.edge || 'n/a'}, " \
                 "CDN #{e.cdn || 'none'}, WAF #{e.waf || 'none'}, SAPI #{e.sapi}"
        lines << "- **Frameworks:** #{e.frameworks.empty? ? 'none observed' : e.frameworks.map { |f| "#{f.name} (#{f.confidence})" }.join(', ')}"
        lines << ""

        lines << "### Evidence"
        lines << ""
        lines << "| Path | Method | Status | Time | Size | Signal |"
        lines << "|---|---|---|---|---|---|"
        result.probes.each do |probe|
          lines << "| #{cell(probe.request_uri)} | #{probe.method} | #{probe.error? ? 'ERR' : probe.status} | " \
                   "#{format('%.0f', probe.elapsed_ms)} ms | #{probe.body_length} B | #{cell(signal(probe))} |"
        end
        lines << ""

        lines << "### ATT&CK assessment path"
        lines << ""
        lines << "| Technique | Tactic | Name | Note |"
        lines << "|---|---|---|---|"
        result.assessment_path.each do |technique|
          lines << "| [#{technique.id}](#{technique.url}) | #{cell(technique.tactic)} | " \
                   "#{cell(technique.name)} | #{cell(technique.note)} |"
        end
        lines << ""

        if result.attack_chain.empty?
          lines << "**ATT&CK kill chain:** none — no confirmed vulnerable interpreter."
        else
          lines << "### ATT&CK kill chain (confirmed exposure)"
          lines << ""
          lines << "| Technique | Tactic | Name | Note |"
          lines << "|---|---|---|---|"
          result.attack_chain.each do |technique|
            lines << "| [#{technique.id}](#{technique.url}) | #{cell(technique.tactic)} | " \
                     "#{cell(technique.name)} | #{cell(technique.note)} |"
          end
        end
        lines << ""

        lines << "### Detection opportunities"
        lines << ""
        result.detections.each do |detection|
          lines << "- **#{detection.layer} — #{detection.control}:** #{detection.detail}"
        end
        lines << ""

        if options.redteam && !result.red_team.empty?
          lines << "### Red-team notes"
          lines << ""
          result.red_team.each { |note| lines << "- #{note}" }
          lines << ""
        end

        if options.toolchain && !result.tooling.empty?
          lines << "### Toolchain"
          lines << ""
          result.tooling.group_by(&:phase).each do |phase, entries|
            lines << "**#{phase}**"
            lines << ""
            entries.each do |entry|
              lines << "- `#{entry.tool}` — #{entry.purpose} _Relevance:_ #{entry.relevance}"
            end
            lines << ""
          end
        end

        lines << "### Next actions"
        lines << ""
        result.next_actions.each do |action|
          suffix = action.authorized ? " _(authorized)_" : ""
          lines << "- **#{action.label}**#{suffix}"
          lines << "  ```sh"
          lines << "  #{action.command}"
          lines << "  ```"
          lines << "  #{action.why}"
        end
        lines << ""

        lines << "### Remediation"
        lines << ""
        result.remediation.each { |step| lines << "- [ ] #{step}" }
        lines << ""

        lines << "### Technical summary"
        lines << ""
        lines << "- **Hackability:** #{h.label} · ratio #{h.ratio.nil? ? 'n/a' : format('%.2f', h.ratio)} · " \
                 "positive #{h.positive} / negative #{h.negative} / neutral #{h.neutral}"
        lines << "- **Friction:** #{result.risk[:friction][:level]}"
        h.signals.each do |signal|
          lines << "  - #{signal.direction == :positive ? '+' : signal.direction == :negative ? '-' : '0'} " \
                   "#{signal.label}"
        end
        lines << "- **Reliability:** #{h.reliability}"
        lines << "- **Impact:** #{h.impact}"
        lines << ""

        if options.verbose && !result.trace.lines.empty?
          lines << "<details><summary>Request trace</summary>"
          lines << ""
          lines << "```"
          result.trace.lines.each { |line| lines << line }
          lines << "```"
          lines << ""
          lines << "</details>"
          lines << ""
        end
      end

      def self.risk_text(result)
        score = result.risk[:score]
        score.nil? ? "n/a (#{result.risk[:grade]})" : "#{format('%.1f', score)}/10 (#{result.risk[:grade]})"
      end

      def self.evidence_cell(result)
        coverage = result.fingerprint[:coverage] || {}
        "#{coverage[:usable].to_i}/#{coverage[:attempted].to_i}"
      end

      def self.signal(probe)
        return "control" if probe.purpose.to_s.start_with?("control")
        return "discovery" if probe.purpose.to_s.start_with?("discovery")
        return probe.error_kind.to_s if probe.error?
        return "denied" if probe.denied?
        return "not found" if probe.not_found?
        return "redirect" if probe.redirect?
        return "server error" if probe.server_error?

        markers = probe.php_markers.map { |marker| marker[:kind] }
        markers.empty? ? "ok" : markers.uniq.join(", ")
      end

      def self.cell(value)
        Sanitize.markdown_cell(value.to_s)
      end
    end
  end
end
