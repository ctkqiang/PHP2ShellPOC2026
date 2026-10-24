# frozen_string_literal: true

require_relative "../layout"
require_relative "../risk"
require_relative "../sanitize"
require_relative "../summary"

module PHP2ShellPOC2026
  module Report
    # Human-readable report. The default view is deliberately a dashboard:
    # one findings table, a short assessment card per target, an evidence
    # table, and a numbered next-actions list. Long ATT&CK notes, detection
    # details and technical signals are still available with -v, but they do
    # not bury the answer.
    #
    # The honesty rule from 2.x is unchanged: a blocked host prints BLOCK and
    # n/a, not NOT HACKABLE and 0.00.
    class Text
      VERDICT_CODE = {
        vulnerable: "VULN",
        eol: "EOL",
        patched: "PATCH",
        unknown: "UNK",
        no_php: "NO-PHP",
        inconclusive: "INCON"
      }.freeze

      ACCESS_CODE = {
        open: "OPEN",
        blocked: "BLOCK",
        restricted: "RESTR",
        auth_wall: "AUTH",
        rate_limited: "RATE",
        soft_404: "SOFT",
        server_error: "5XX",
        unreachable: "DEAD",
        unknown: "?"
      }.freeze

      ACCESS_LABEL = {
        open: "open",
        blocked: "blocked",
        restricted: "restricted",
        auth_wall: "auth wall",
        rate_limited: "rate limited",
        soft_404: "soft-404",
        server_error: "server error",
        unreachable: "unreachable",
        unknown: "unknown"
      }.freeze

      def initialize(results, options, summary: nil, meta: {})
        @results = results
        @options = options
        @summary = summary || Summary.compute(results, meta: meta)
        @meta    = meta
      end

      def render
        lines = []
        banner(lines)
        summary_table(lines)
        bottom_line(lines)
        legend(lines) unless @options.quiet
        unless @options.quiet
          @results.each do |result|
            target_block(lines, result)
            lines << ""
          end
        end
        run_summary(lines)
        tip(lines) unless @options.quiet
        lines.join("\n") + "\n"
      end

      private

      def banner(lines)
        return if @options.no_banner || @options.quiet

        Layout.wrap("php2shell-poc2026 #{VERSION} — passive PHP exposure triage", Layout.width)
              .each { |line| lines << line }
        Layout.wrap("profile #{@options.profile} · #{@summary[:total]} target#{@summary[:total] == 1 ? '' : 's'} · " \
                    "#{@summary[:requests]} requests · #{format_duration(@summary[:duration_ms])} · " \
                    "#{@summary[:generated_at]}", Layout.width)
              .each { |line| lines << line }
        Layout.wrap("Authorized assessments only. GET requests only; no payloads, no state-changing verbs.",
                    Layout.width)
              .each { |line| lines << line }
        lines << ""
      end

      # The first thing a reader sees. One row per target, only the columns
      # needed to decide what to open next.
      def summary_table(lines)
        rows = @results.map do |result|
          [
            Sanitize.terminal(result.target.display, max: 200),
            verdict_code(result.verdict),
            access_code(result.verdict.access&.state),
            version_short(result.verdict),
            risk_cell(result),
            evidence_cell(result)
          ]
        end

        lines << "  FINDINGS"
        Layout.table(%w[TARGET VERDICT ACCESS VERSION RISK EVID], rows).each { |line| lines << line }
        lines << ""
      end

      def bottom_line(lines)
        if @results.empty?
          lines << "  Bottom line: no targets were scanned."
          lines << ""
          return
        end

        exposed    = @summary[:exposed]
        unverified = @summary[:unverified]
        text =
          if exposed.positive?
            result = "#{exposed} exposed target#{exposed == 1 ? '' : 's'} — patch or upgrade now."
            if unverified.positive?
              result += " #{unverified} other target#{unverified == 1 ? '' : 's'} could not be assessed."
            end
            result
          elsif unverified.positive?
            reasons = unverified_reasons
            result = "no confirmed exposure; #{unverified} target#{unverified == 1 ? '' : 's'} " \
                     "could not be assessed"
            result += " (#{reasons})" unless reasons.empty?
            "#{result}. Do not treat this as clean."
          else
            "no exposure confirmed on the paths tested."
          end

        hung(lines, "  Bottom line: ", text)
        lines << ""
      end

      def legend(lines)
        entries = [
          "VULN vulnerable · EOL end-of-life · PATCH patched · UNK unverified",
          "NO-PHP no PHP · INCON inconclusive · BLOCK blocked · RESTR restricted",
          "AUTH auth wall · RATE rate limited · SOFT soft-404 · DEAD unreachable · 5XX server error",
          "EVID = usable / attempted probes"
        ]
        entries.each_with_index do |entry, entry_index|
          prefix = entry_index.zero? ? "  Legend: " : "          "
          Layout.wrap(entry, Layout.width - prefix.length).each_with_index do |line, line_index|
            lines << (line_index.zero? ? "#{prefix}#{line}" : "          #{line}")
          end
        end
        lines << ""
      end

      def target_block(lines, result)
        v  = result.verdict
        e  = result.environment
        s  = v.attack_surface

        lines << ""
        lines << "  #{Sanitize.terminal(result.target.display, max: Layout.width - 4)}"
        lines << "  #{'-' * [Layout.width - 4, 20].max}"

        overview_table(lines, result)
        field(lines, "Reason", v.reason) if v.reason && !v.reason.empty?
        field(lines, "Surface", surface_text(s))
        if @options.verbose && e.sapi_rationale
          field(lines, "SAPI note", e.sapi_rationale)
        end

        evidence_table(lines, result)
        attack_section(lines, result)
        detections_section(lines, result)
        red_team_section(lines, result) if @options.redteam
        toolchain_section(lines, result) if @options.toolchain
        trace_section(lines, result) if @options.verbose
        technical_section(lines, result) if @options.verbose || result.exposed?
        next_actions_section(lines, result)
        remediation_section(lines, result) if @options.verbose || result.exposed?
      end

      # Short values only. Long prose belongs in the "why" field below, where
      # it can wrap without turning the table into a ragged paragraph.
      def overview_table(lines, result)
        v = result.verdict
        e = result.environment
        h = result.hackability
        value_limit = [Layout.width - 24, 24].max

        rows = [
          ["Verdict", v.label],
          ["Access", access_label(v.access&.state)],
          ["Exposure", risk_text(result)],
          ["Confidence", v.confidence],
          ["Version", version_table_text(v)],
          ["Evidence", "#{evidence_cell(result)} probes usable"],
          ["Hackability", hackability_text(h)],
          ["Control", control_text(v.access)],
          ["Server", e.server || "n/a"],
          ["Edge", e.edge || "n/a"],
          ["CDN/WAF", "#{e.cdn || 'none'} / #{e.waf || 'none'}"],
          ["SAPI", e.sapi || "n/a"],
          ["Framework", framework_text(e)],
          ["Friction", friction_text(result)]
        ]
        rows << ["Hosting", e.hosting] if e.hosting && e.hosting != "unknown"
        rows = rows.map { |label, value| [label, Sanitize.terminal(value.to_s, max: value_limit)] }

        lines << ""
        lines << "  ASSESSMENT"
        Layout.table(%w[FIELD VALUE], rows, margin: "  ").each { |line| lines << line }
      end

      def evidence_table(lines, result)
        lines << ""
        lines << "  EVIDENCE"

        control = result.fingerprint[:control]
        if control
          similarity = control[:similarity]
          similarity = similarity ? format("%.2f", similarity) : "n/a"
          hung(lines, "    control: ",
               "#{Sanitize.url(control[:path], max: 60)} → #{control[:status] || 'error'} " \
               "(similarity #{similarity})")
        end

        rows = result.probes.map do |probe|
          [
            Sanitize.url(probe.request_uri, max: 80),
            probe.method,
            probe.error? ? "ERR" : probe.status.to_s,
            format_ms(probe.elapsed_ms),
            format_bytes(probe.body_length),
            Sanitize.terminal(probe_signal(probe), max: 18)
          ]
        end

        if rows.empty?
          lines << "    (no probes recorded)"
        else
          Layout.table(%w[PATH METHOD STATUS TIME SIZE SIGNAL], rows, margin: "    ").each { |line| lines << line }
        end
      end

      def attack_section(lines, result)
        lines << ""
        lines << "  ATT&CK"

        assessment = result.assessment_path
                           .group_by(&:id)
                           .map { |id, entries| "#{id} #{entries.first.name}" }
                           .join(" · ")
        hung(lines, "    assessment: ", assessment.empty? ? "none" : assessment)

        if result.attack_chain.empty?
          hung(lines, "    kill chain: ", "none (no confirmed vulnerable interpreter)")
        else
          chain = result.attack_chain.map { |t| "#{t.id} #{t.name}" }.join(" → ")
          hung(lines, "    kill chain: ", chain)
        end

        return unless @options.verbose

        lines << ""
        lines << "    Assessment detail:"
        result.assessment_path.each do |technique|
          hung(lines, "      #{technique.id.ljust(9)} ", "#{technique.tactic} — #{technique.name}")
          hung(lines, "                ", technique.note)
        end

        return if result.attack_chain.empty?

        lines << "    Kill-chain detail:"
        result.attack_chain.each do |technique|
          hung(lines, "      #{technique.id.ljust(9)} ", "#{technique.tactic} — #{technique.name}")
          hung(lines, "                ", technique.note)
        end
      end

      def detections_section(lines, result)
        lines << ""
        lines << "  DETECTIONS"

        if result.detections.empty?
          lines << "    (none)"
          return
        end

        result.detections.each do |detection|
          hung(lines, "    [#{detection.layer}] ", detection.control)
          hung(lines, "        ", detection.detail) if @options.verbose
        end
      end

      def red_team_section(lines, result)
        lines << ""
        lines << "  RED-TEAM NOTES"
        result.red_team.each { |note| hung(lines, "    - ", note) }
      end

      # A table, not a wall of prose. Tool name and phase are the scan
      # columns; purpose is the one that needs wrapping.
      def toolchain_section(lines, result)
        lines << ""
        lines << "  TOOLCHAIN#{@options.toolchain_full ? ' (full catalogue)' : ' (relevant)'}"

        result.tooling.group_by(&:phase).each do |phase, entries|
          lines << "    #{phase}"
          entries.each do |entry|
            hung(lines, "      #{entry.tool} — ", entry.purpose)
            hung(lines, "          relevance: ", entry.relevance)
            hung(lines, "          ATT&CK: ", entry.techniques.join(", ")) unless entry.techniques.empty?
          end
        end

        if !@options.authorized && result.tooling.none?(&:offensive)
          lines << "    (Offensive and post-exploitation entries are omitted; pass --authorized to include them.)"
        end
      end

      def trace_section(lines, result)
        lines << ""
        lines << "  TRACE"
        result.trace.lines.each { |line| lines << "    #{Sanitize.terminal(line, max: Layout.width - 4)}" }
      end

      def technical_section(lines, result)
        h = result.hackability
        lines << ""
        lines << "  TECHNICAL DETAIL"
        field(lines, "hackability", "#{h.label}   ratio #{h.ratio.nil? ? 'n/a' : format('%.2f', h.ratio)}   " \
                                     "confidence #{h.confidence}   coverage #{evidence_cell(result)}")
        field(lines, "evidence", "positive #{h.positive} / negative #{h.negative} / neutral #{h.neutral}")
        lines << "    signals:"
        if h.signals.empty?
          lines << "      (none)"
        else
          h.signals.each do |signal|
            marker = case signal.direction
                     when :positive then "+#{signal.weight}"
                     when :negative then "-#{signal.weight}"
                     else " 0"
                     end
            hung(lines, "      #{marker.rjust(3)}  ", signal.label)
          end
        end

        friction = result.risk[:friction]
        if friction && !friction[:factors].empty?
          factors = friction[:factors].map { |factor| factor[:note] }.join("; ")
          field(lines, "friction", "#{friction[:level]} — #{factors}")
        end
        lines << "    prerequisites:"
        h.prerequisites.each { |item| hung(lines, "      - ", item) }
        field(lines, "reliability", h.reliability)
        field(lines, "impact", h.impact)
      end

      def next_actions_section(lines, result)
        lines << ""
        lines << "  NEXT ACTIONS"
        result.next_actions.each_with_index do |action, index|
          label = action.authorized ? "#{action.label} [authorized]" : action.label
          hung(lines, "    #{index + 1}. ", label)

          command_lines = Layout.wrap(Sanitize.terminal(action.command), Layout.width - 10)
          lines << "       $ #{command_lines.shift}"
          command_lines.each { |line| lines << "         #{line}" }

          hung(lines, "       ", "why: #{action.why}") if action.why && !action.why.empty?
        end
      end

      def remediation_section(lines, result)
        lines << ""
        lines << "  REMEDIATION"
        result.remediation.each { |step| hung(lines, "    - ", step) }
      end

      def run_summary(lines)
        s = @summary
        lines << ""
        lines << "  RUN SUMMARY"
        summary_field(lines, "targets", "#{s[:total]} (exposed #{s[:exposed]}, patched #{s[:patched]}, " \
                                      "no PHP #{s[:no_php]})")
        unverified = "#{s[:unverified]}"
        reasons = unverified_reasons
        unverified += " (#{reasons})" unless reasons.empty?
        summary_field(lines, "unverified", unverified)
        summary_field(lines, "errors", s[:errors].to_s)
        summary_field(lines, "coverage", "#{s[:coverage][:usable]}/#{s[:coverage][:attempted]} probes usable " \
                                        "(#{format('%.1f', s[:coverage][:percent])}%)")
        summary_field(lines, "assessable", "#{s[:assessable]}/#{s[:total]} targets")
        summary_field(lines, "requests", "#{s[:requests]} in #{format_duration(s[:duration_ms])}")
        summary_field(lines, "scope", "#{s[:scope_skipped]} skipped outside scope") if s[:scope_skipped].positive?
      end

      def tip(lines)
        lines << ""
        entries = [
          "Tip: -v full ATT&CK/detection detail; -c toolchain; -r red-team notes.",
          "--format json|markdown|sarif|csv|ndjson; --dry-run plan; --scope scope.txt.",
          "Exit codes: 0 clear/unverified, 1 error, 2 exposed, 3 inconclusive",
          "(--fail-on inconclusive), 4 scope violation."
        ]
        entries.each_with_index do |entry, index|
          prefix = index.zero? ? "  " : "       "
          Layout.wrap(entry, Layout.width - prefix.length).each { |line| lines << "#{prefix}#{line}" }
        end
      end

      # -- helpers ----------------------------------------------------------

      def field(lines, label, value, width: 11)
        prefix = "  #{label.ljust(width)}: "
        Layout.wrap_hanging(prefix, Sanitize.terminal(value), prefix.length).each { |line| lines << line }
      end

      # Run-summary labels are a little shorter than the assessment table's
      # widest label ("Hackability"), so use their own width to keep the
      # stable "unverified: N" string aligned and greppable.
      def summary_field(lines, label, value)
        field(lines, label, value, width: 10)
      end

      def hung(lines, prefix, text)
        Layout.wrap_hanging(prefix, Sanitize.terminal(text), prefix.length).each { |line| lines << line }
      end

      def unverified_reasons
        s = @summary
        reasons = []
        reasons << "blocked #{s[:blocked]}" if s[:blocked].positive?
        reasons << "auth wall #{s[:auth_wall]}" if s[:auth_wall].positive?
        reasons << "rate limited #{s[:rate_limited]}" if s[:rate_limited].positive?
        reasons << "soft-404 #{s[:soft_404]}" if s[:soft_404].positive?
        reasons << "unreachable #{s[:unreachable]}" if s[:unreachable].positive?
        reasons << "unknown version #{s[:unknown]}" if s[:unknown].positive?
        reasons.join(", ")
      end

      def verdict_code(verdict)
        VERDICT_CODE.fetch(verdict.status, "?")
      end

      def access_code(state)
        ACCESS_CODE.fetch(state, "?")
      end

      def access_label(state)
        ACCESS_LABEL.fetch(state, "unknown")
      end

      def risk_cell(result)
        score = result.risk[:score]
        return "n/a UNK" if score.nil?

        "#{format('%.1f', score)} #{Risk.grade_code(result.risk[:grade])}"
      end

      def risk_text(result)
        score = result.risk[:score]
        return "n/a (#{result.risk[:grade]})" if score.nil?

        "#{format('%.1f', score)}/10 (#{result.risk[:grade]})"
      end

      def evidence_cell(result)
        coverage = result.fingerprint[:coverage] || {}
        "#{coverage[:usable].to_i}/#{coverage[:attempted].to_i}"
      end

      def version_short(verdict)
        return "unknown" unless verdict.version

        text = verdict.version.to_s
        text += " (branch)" if verdict.version_precision == :minor
        text
      end

      def version_table_text(verdict)
        return "unknown" unless verdict.version

        text = verdict.version.to_s
        text += " (branch)" if verdict.version_precision == :minor
        text += " · floor #{verdict.fix_floor}" if verdict.fix_floor
        text
      end

      def hackability_text(h)
        ratio = h.ratio.nil? ? "n/a" : format("%.2f", h.ratio)
        "#{h.label} (ratio #{ratio})"
      end

      def control_text(access)
        return "none" unless access&.control

        status = access.control[:status] || "error"
        similarity = access.control[:similarity]
        similarity ? "#{status} (similarity #{format('%.2f', similarity)})" : status.to_s
      end

      def friction_text(result)
        friction = result.risk[:friction]
        return "n/a" unless friction && !friction[:factors].empty?

        factors = friction[:factors].map { |factor| factor[:factor].to_s.tr("_", " ") }.uniq.join(", ")
        "#{friction[:level]} (#{factors})"
      end

      def surface_text(surface)
        "PHP #{bool_text(surface[:php_detected])} · " \
          "phpinfo #{bool_text(surface[:phpinfo_exposed])} · " \
          "live .php #{bool_text(surface[:php_paths_live])} · " \
          "upload #{bool_text(surface[:upload_progress])} · " \
          "errors #{bool_text(surface[:php_errors])}"
      end

      def framework_text(environment)
        return "none observed" if environment.frameworks.empty?

        environment.frameworks.map { |f| "#{f.name} (#{f.confidence})" }.join(", ")
      end

      def bool_text(value)
        value ? "yes" : "no"
      end

      def probe_signal(probe)
        return "control" if probe.purpose.to_s.start_with?("control")
        return "discovery" if probe.purpose.to_s.start_with?("discovery")
        return probe.error_kind.to_s if probe.error?
        return "denied" if probe.denied?
        return "rate limited" if probe.rate_limited?
        return "not found" if probe.not_found?
        return "server error" if probe.server_error?
        return "redirect" if probe.redirect?

        markers = probe.php_markers.map { |marker| marker[:kind].to_s.tr("_", "-") }
        markers << "phpinfo" if probe.phpinfo?
        markers << "fpm-404" if probe.php_fpm_not_found?
        return markers.uniq.join(",") unless markers.empty?

        "ok"
      end

      def format_bytes(bytes)
        bytes = bytes.to_i
        if bytes < 1024
          "#{bytes} B"
        elsif bytes < 1024 * 1024
          format("%.1f KB", bytes / 1024.0)
        else
          format("%.1f MB", bytes / (1024.0 * 1024.0))
        end
      end

      def format_ms(ms)
        ms = ms.to_f
        ms < 1000 ? format("%.0f ms", ms) : format("%.2f s", ms / 1000.0)
      end

      def format_duration(ms)
        ms = ms.to_f
        ms < 1000 ? format("%.0f ms", ms) : format("%.2f s", ms / 1000.0)
      end
    end
  end
end
