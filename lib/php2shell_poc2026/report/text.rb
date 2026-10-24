# frozen_string_literal: true

require_relative "../i18n"
require_relative "../layout"
require_relative "../sanitize"
require_relative "../style"
require_relative "../summary"

module PHP2ShellPOC2026
  module Report
    # Human-readable report. The default view is deliberately a dashboard:
    # the answer first, then one findings table, a short assessment card per
    # target, an evidence table, and a numbered next-actions list. Long
    # ATT&CK notes, detection details and technical signals are still
    # available with -v, but they do not bury the answer.
    #
    # The honesty rule from 2.x is unchanged: a blocked host prints BLOCK and
    # n/a, not NOT HACKABLE and 0.00.
    class Text
      VERDICT_LABEL = {
        vulnerable: "VULNERABLE",
        eol: "END-OF-LIFE",
        patched: "PATCHED",
        unknown: "UNVERIFIED",
        no_php: "NO PHP",
        inconclusive: "INCONCLUSIVE"
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
        @paint   = Style.painter(options)
      end

      def render
        I18n.with_locale(@options.locale) { build_report }
      end

      private

      def build_report
        lines = []
        banner(lines)
        bottom_line(lines)
        summary_table(lines)
        legend(lines) unless @options.quiet
        unless @options.quiet
          @results.each { |result| target_block(lines, result) }
        end
        run_summary(lines)
        tip(lines) unless @options.quiet
        lines.pop while lines.last == ""
        lines.join("\n") + "\n"
      end

      def t(key, default, **vars)
        I18n.t("text.#{key}", default: default, **vars)
      end

      def banner(lines)
        return if @options.no_banner || @options.quiet

        title = t("banner.title", "php2shell-poc2026 %{version} — PHP2Shell vulnerability check", version: VERSION)
        Layout.wrap(title, Layout.width).each { |line| lines << @paint.call(line, :bold, :cyan) }

        count    = @summary[:total]
        requests = @summary[:requests]
        target_word = t(count == 1 ? "banner.target" : "banner.targets",
                        count == 1 ? "target" : "targets")
        request_word = t(requests == 1 ? "banner.request" : "banner.requests",
                         requests == 1 ? "request" : "requests")
        meta = t("banner.meta",
                 "scan depth %{profile} · %{count} %{target_word} · %{requests} %{request_word} · " \
                 "%{duration} · %{generated_at}",
                 profile: @options.profile, count: count, target_word: target_word,
                 requests: @summary[:requests], request_word: request_word,
                 duration: format_duration(@summary[:duration_ms]),
                 generated_at: @summary[:generated_at])
        Layout.wrap(meta, Layout.width).each { |line| lines << @paint.call(line, :dim) }

        authorized = t("banner.authorized",
                       "Authorized assessments only. GET requests only; no payloads, no state-changing verbs.")
        Layout.wrap(authorized, Layout.width).each { |line| lines << @paint.call(line, :dim) }

        if @options.browser_ua
          browser = t("banner.browser_ua",
                      "User-Agent: browser compatibility mode — only use this when your authorization permits it.")
          Layout.wrap(browser, Layout.width).each { |line| lines << @paint.call(line, :yellow) }
        end
        blank(lines)
      end

      # The answer goes above the table, not after it. A reader should be
      # able to stop after three lines and still know whether anything needs
      # doing.
      def bottom_line(lines)
        if @results.empty?
          hung(lines, t("bottom_line.label", "  Bottom line: "), t("bottom_line.none", "no targets were scanned."))
          blank(lines)
          return
        end

        hackable = @summary[:hackable]
        unknown  = @summary[:decision_unknown]
        text, tone =
          if hackable.positive?
            result = t("bottom_line.exposed",
                       "YES — %{count} %{target_word} hackable via PHP2Shell; patch or upgrade now.",
                       count: hackable, target_word: target_word(hackable))
            if unknown.positive?
              result += " #{t('bottom_line.other_unverified',
                              '%{count} other %{target_word} could not be assessed.',
                              count: unknown, target_word: target_word(unknown))}"
            end
            [result, :red]
          elsif unknown.positive?
            reasons = unverified_reasons
            result = t("bottom_line.unverified",
                       "UNKNOWN — the scanner could not check %{count} %{target_word}",
                       count: unknown, target_word: target_word(unknown))
            result += t("bottom_line.reasons", " (%{reasons})", reasons: reasons) unless reasons.empty?
            [t("bottom_line.unverified_full", "%{result}. Do not treat this as safe.", result: result), :yellow]
          else
            [t("bottom_line.clean", "NO — no target hackable on the pages tested."), :green]
          end

        styled_hung(lines, t("bottom_line.label", "  Bottom line: "), text, :bold, tone)
        styled_hung(lines, t("bottom_line.next_label", "  Next:        "), next_step, :bold, :cyan)
        blank(lines)
      end

      def next_step
        if @summary[:hackable].positive?
          if @summary[:total] > 1
            return t("next.patch_many", "patch every exposed host first; per-host fixes are below.")
          end

          return t("next.patch_one", "patch or upgrade PHP on the exposed host; see HOW TO FIX IT.")
        end

        if @summary[:total] > 1
          return t("next.multi", "work through the per-host NEXT STEPS below, starting with any unknown host.")
        end

        if @summary[:blocked].positive?
          if (page = blocked_page)
            if page.vendor
              t("next.blocked_browser_ua",
                "the edge blocked the scanner (%{vendor}); retry with --browser-ua if authorized, or check the " \
                "PHP version on the host.", vendor: page.vendor)
            else
              t("next.blocked_browser_ua_generic",
                "the edge blocked the scanner; retry with --browser-ua if authorized, or check the PHP version " \
                "on the host.")
            end
          else
            t("next.blocked", "retry from an approved connection, or check the PHP version on the host.")
          end
        elsif @summary[:auth_wall].positive?
          t("next.auth_wall", "retry with authorized credentials if your authorization allows it.")
        elsif @summary[:rate_limited].positive?
          t("next.rate_limited", "slow the scan down with --delay 2000 --threads 1 and retry.")
        elsif @summary[:soft_404].positive?
          t("next.soft_404", "run a deeper scan or test a different host that serves the application normally.")
        elsif @summary[:unreachable].positive?
          t("next.unreachable", "check DNS, routing and the TLS certificate before drawing any conclusion.")
        elsif @summary[:decision_unknown].positive?
          t("next.unverified", "run a deeper scan or check the PHP version on the host.")
        elsif @summary[:no_php].positive?
          t("next.no_php", "no PHP was seen on the paths tested. Check sibling hosts or other ports if this route should run PHP.")
        else
          t("next.none", "no action required; re-scan after the next PHP update.")
        end
      end

      def target_word(count)
        t(count == 1 ? "common.target" : "common.targets", count == 1 ? "target" : "targets")
      end

      # The first table a reader sees. It answers the question directly:
      # hackable, not hackable, or unknown. Technical columns belong in
      # the verbose assessment, not here.
      def summary_table(lines)
        rows = @results.map do |result|
          [
            Sanitize.terminal(result.target.display, max: 200),
            paint_answer(result),
            version_cell(result.verdict),
            Sanitize.terminal(note_text(result), max: 60)
          ]
        end

        lines << @paint.call("  #{t('summary.title', 'FINDINGS')}", :bold, :cyan)
        headers = [
          t("summary.target", "TARGET"), t("summary.hackable", "HACKABLE?"),
          t("summary.php", "PHP"), t("summary.note", "NOTE")
        ]
        Layout.table(headers, rows).each { |line| lines << line }
        blank(lines)
      end

      def legend(lines)
        entries = [
          t("legend.line1",
            "YES = hackable · NO = not hackable on the pages tested · UNKNOWN = could not be checked"),
          t("legend.line2", 'UNKNOWN is never the same as "NO".')
        ]
        indent = " " * Layout.display_width(t("legend.label", "  Legend: "))
        entries.each_with_index do |entry, entry_index|
          prefix = entry_index.zero? ? t("legend.label", "  Legend: ") : indent
          Layout.wrap(entry, Layout.width - Layout.display_width(prefix)).each_with_index do |line, line_index|
            lines << (line_index.zero? ? "#{@paint.call(prefix, :dim)}#{line}" : "#{indent}#{line}")
          end
        end
        blank(lines)
      end

      def target_block(lines, result)
        blank(lines)
        title = Sanitize.terminal(result.target.display, max: Layout.width - 4)
        lines << "  #{@paint.call(title, :bold)}"
        lines << "  #{'-' * [Layout.width - 4, 20].max}"

        decision_card(lines, result)
        summary_card(lines, result)

        if @options.verbose
          overview_table(lines, result)
          if result.verdict.reason && !result.verdict.reason.empty?
            field(lines, t("field.reason", "Full reason"), result.verdict.reason)
          end
          field(lines, t("field.surface", "Observed PHP features"),
                surface_text(result.verdict.attack_surface, result.verdict))
          if result.environment.sapi_rationale
            field(lines, t("field.sapi_note", "PHP runtime note"), result.environment.sapi_rationale)
          end
          evidence_table(lines, result)
          attack_section(lines, result)
          detections_section(lines, result)
          technical_section(lines, result)
        end

        red_team_section(lines, result) if @options.redteam
        toolchain_section(lines, result) if @options.toolchain
        next_actions_section(lines, result)
        remediation_section(lines, result) if @options.verbose
        trace_section(lines, result) if @options.verbose
      end

      # Plain-language answer card. No scores, ratios, SAPI names or ATT&CK
      # identifiers; those live in the verbose technical section.
      def summary_card(lines, result)
        v = result.verdict
        section(lines, t("section.plain", "WHAT THIS MEANS"))
        field(lines, t("plain.result", "Result"), result_word(result.hackability.rating))
        field(lines, t("plain.why", "Why"), plain_reason(result))
        field(lines, t("plain.confidence", "Confidence"), confidence_plain(v))
        field(lines, t("plain.evidence", "Evidence"), coverage_plain(result))
        field(lines, t("plain.php", "PHP"), version_plain(v))
        if result.environment.block_page
          field(lines, t("plain.blocked_by", "Blocked by"),
                block_page_text(result.environment.block_page))
        end
        if (fix = fix_text(v))
          field(lines, t("plain.fix", "Fix"), fix)
        end
      end

      # The first thing a reader sees per target: the answer to "can this
      # host be hacked by PHP2Shell?", as a decision instead of a ratio.
      # Evidence lives in the tables below; this card only commits to the
      # answer and the one action that follows from it.
      def decision_card(lines, result)
        h = result.hackability
        headline, statement, tone =
          case h.rating
          when :exposed
            [t("decision.yes_line", "YES — this host can be hacked by PHP2Shell."),
             t("decision.exposed",
               "A remote attacker could exploit this host without logging in."), :red]
          when :likely
            [t("decision.likely_line", "LIKELY — treat this host as hackable until the PHP version is confirmed."),
             t("decision.likely",
               "The evidence points to exposure, but the version was not confirmed."), :yellow]
          when :not_exposed
            [t("decision.no_line", "NO — no PHP2Shell exposure was found on the pages tested."),
             t("decision.not_exposed",
               "The PHP version found is fixed, or no PHP was found on the pages tested."), :green]
          else
            [t("decision.unknown_line", "UNKNOWN — the scanner could not tell."),
             t("decision.inconclusive",
               "The scanner could not see enough of the host to answer safely."), :yellow]
          end

        prefix = "  #{t('decision.key', 'DECISION')}#{t('common.colon', ':')}"
        prefix = Layout.pad(prefix, [12, Layout.display_width(prefix) + 1].max)
        styled_hung(lines, prefix, headline, :bold, tone)
        hang = " " * Layout.display_width(prefix)
        hung(lines, hang, statement)
        if (block_page = result.environment.block_page)
          hung(lines, hang,
               t("decision.blocked_by", "Blocked by %{vendor}: %{summary}",
                 vendor: block_page.vendor || t("common.edge", "edge"),
                 summary: block_page.summary))
        end
        if result.verdict.version && result.verdict.confidence.to_s == "low" &&
           result.verdict.access && !result.verdict.access.open?
          hung(lines, hang,
               t("decision.caveat",
                 "Caveat: the version came from a blocked response; confirm it from an approved connection " \
                 "before acting on this decision."))
        end
        return if h.action.to_s.empty?

        action_prefix = "  #{t('decision.action_key', 'ACTION')}#{t('common.colon', ':')}"
        action_prefix = Layout.pad(action_prefix, [12, Layout.display_width(action_prefix) + 1].max)
        styled_hung(lines, action_prefix, h.action, tone)
      end

      # Short values only. Long prose belongs in the Reason/Surface fields
      # below, where it can wrap without turning the table into a ragged
      # paragraph. Rows with nothing to say are omitted rather than filled
      # with "n/a": a blocked host does not have a framework, and printing
      # "none observed" six times just makes the real signal harder to find.
      def overview_table(lines, result)
        v = result.verdict
        e = result.environment
        h = result.hackability
        value_limit = [Layout.width - 24, 24].max

        rows = [
          [t("assessment.verdict", "Technical verdict"), verdict_label(v)],
          [t("assessment.access", "Access path"), access_detail(v.access)],
          [t("assessment.exposure", "Severity (CVSS-like)"), risk_text(result)],
          [t("assessment.confidence", "Confidence"), confidence_label(v.confidence)],
          [t("assessment.version", "Version"), version_table_text(v)],
          [t("assessment.evidence", "Pages usable"),
           t("assessment.probes_usable", "%{count} pages usable", count: evidence_cell(result))],
          [t("assessment.hackability", "Evidence rating"), hackability_text(h)],
          [t("assessment.control", "Control page"), control_text(v.access)]
        ]
        rows << [t("assessment.server", "Server"), e.server] if present?(e.server)
        rows << [t("assessment.edge", "Edge"), e.edge] if present?(e.edge) && e.edge != e.server
        rows << [t("assessment.cdn", "CDN"), e.cdn] if present?(e.cdn)
        rows << [t("assessment.waf", "Edge protection (WAF)"), edge_text(e.waf)] if present?(e.waf)
        rows << [t("assessment.block_page", "Block page"), block_page_text(e.block_page)] if e.block_page
        rows << [t("assessment.sapi", "PHP runtime (SAPI)"), sapi_label(e.sapi)] if present?(e.sapi) && e.sapi != "unknown"
        rows << [t("assessment.framework", "Framework"), framework_text(e)] unless e.frameworks.empty?
        rows << [t("assessment.hosting", "Hosting"), e.hosting] if present?(e.hosting) && e.hosting != "unknown"
        rows << [t("assessment.friction", "Exploit difficulty"), friction_text(result)]

        rows = rows.map { |label, value| [label, Sanitize.terminal(value.to_s, max: value_limit)] }
        rows[0][1] = paint_verdict(rows[0][1], v.status)

        section(lines, t("section.assessment", "TECHNICAL DETAILS"))
        headers = [t("assessment.field", "FIELD"), t("assessment.value", "VALUE")]
        Layout.table(headers, rows, margin: "  ").each { |line| lines << line }
      end

      def evidence_table(lines, result)
        section(lines, t("section.evidence", "PAGES CHECKED"))

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
          lines << "    #{t('evidence.none', '(no probes recorded)')}"
        else
          headers = [
            t("evidence.path", "PATH"), t("evidence.method", "METHOD"),
            t("evidence.status", "STATUS"), t("evidence.time", "TIME"),
            t("evidence.size", "SIZE"), t("evidence.signal", "SIGNAL")
          ]
          Layout.table(headers, rows, margin: "    ").each { |line| lines << line }
        end
      end

      def attack_section(lines, result)
        section(lines, t("section.attack", "ATTACK PATH (MITRE ATT&CK)"))

        assessment = result.assessment_path
                           .group_by(&:id)
                           .map { |id, entries| "#{id} #{entries.first.name}" }
                           .join(" · ")
        hung(lines, "    #{t('attack.assessment', 'assessment: ')}",
             assessment.empty? ? t("attack.none", "none") : assessment)

        if result.attack_chain.empty?
          hung(lines, "    #{t('attack.kill_chain', 'kill chain: ')}",
               t("attack.no_chain", "none (no confirmed vulnerable interpreter)"))
        else
          chain = result.attack_chain.map { |technique| "#{technique.id} #{technique.name}" }.join(" → ")
          hung(lines, "    #{t('attack.kill_chain', 'kill chain: ')}", chain)
        end

        return unless @options.verbose

        blank(lines)
        lines << "    #{t('attack.assessment_detail', 'Assessment detail:')}"
        result.assessment_path.group_by(&:id).each_value do |entries|
          technique = entries.first
          hung(lines, "      #{technique.id.ljust(9)} ",
               "#{tactic_label(technique.tactic)} — #{technique.name}")
          entries.map(&:note).uniq.each { |note| hung(lines, "                ", note) }
        end

        return if result.attack_chain.empty?

        lines << "    #{t('attack.kill_chain_detail', 'Kill-chain detail:')}"
        result.attack_chain.each do |technique|
          hung(lines, "      #{technique.id.ljust(9)} ",
               "#{tactic_label(technique.tactic)} — #{technique.name}")
          hung(lines, "                ", technique.note)
        end
      end

      def detections_section(lines, result)
        section(lines, t("section.detections", "DEFENDER CHECKS"))

        if result.detections.empty?
          lines << "    #{t('detections.none', '(none)')}"
          return
        end

        result.detections.each do |detection|
          hung(lines, "    [#{detection.layer}] ", detection.control)
          hung(lines, "        ", detection.detail) if @options.verbose
        end
      end

      def red_team_section(lines, result)
        section(lines, t("section.red_team", "ATTACKER NOTES"))
        result.red_team.each { |note| hung(lines, "    - ", note) }
      end

      # One line per tool. The long "relevance" paragraph is what turned the
      # old catalogue into a wall of text; it is reserved for
      # --toolchain-full, where the reader explicitly asked for the whole
      # catalogue and the reasoning behind each entry.
      def toolchain_section(lines, result)
        title = @options.toolchain_full ? t("section.toolchain_full", "TOOLCHAIN (full catalogue)") :
                                          t("section.toolchain", "TOOLCHAIN (relevant)")
        section(lines, title)

        result.tooling.group_by(&:phase).each do |phase, entries|
          lines << "    #{@paint.call(phase_label(phase), :bold)}"
          entries.each do |entry|
            text = entry.purpose
            text += " #{entry.relevance}" if @options.toolchain_full
            hung(lines, "      #{entry.tool} — ", text, hang: 16)
          end
        end

        if !@options.authorized && result.tooling.none?(&:offensive)
          lines << "    #{t('toolchain.omitted', '(Offensive and post-exploitation entries are omitted; pass --authorized to include them.)')}"
        end
      end

      def trace_section(lines, result)
        section(lines, t("section.trace", "REQUEST TRACE"))
        result.trace.lines.each { |line| lines << "    #{Sanitize.terminal(line, max: Layout.width - 4)}" }
      end

      def technical_section(lines, result)
        h = result.hackability
        section(lines, t("section.technical", "TECHNICAL SIGNALS"))
        field(lines, t("technical.hackability", "evidence rating"),
              "#{hackability_label(h.rating)}   #{t('technical.ratio', 'ratio')} " \
              "#{h.ratio.nil? ? t('common.na', 'n/a') : format('%.2f', h.ratio)}   " \
              "#{t('technical.confidence', 'confidence')} #{confidence_label(h.confidence)}   " \
              "#{t('technical.coverage', 'coverage')} #{evidence_cell(result)}")
        field(lines, t("technical.evidence", "evidence"),
              "#{t('technical.positive', 'positive')} #{h.positive} / " \
              "#{t('technical.negative', 'negative')} #{h.negative} / " \
              "#{t('technical.neutral', 'neutral')} #{h.neutral}")
        lines << "    #{t('technical.signals', 'signals:')}"
        if h.signals.empty?
          lines << "      #{t('technical.none', '(none)')}"
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
          factors = friction[:factors].map { |factor| factor[:note] }.join(t("common.detail_separator", "; "))
          field(lines, t("technical.friction", "exploit difficulty"),
                "#{friction_level_label(friction[:level])} — #{factors}")
        end
        lines << "    #{t('technical.prerequisites', 'what an attacker needs:')}"
        h.prerequisites.each { |item| hung(lines, "      - ", item) }
        field(lines, t("technical.reliability", "reliability"), h.reliability)
        field(lines, t("technical.impact", "impact"), h.impact)
      end

      # Default view keeps the four most useful actions. -v restores the full
      # set and the rationale for each one.
      def next_actions_section(lines, result)
        section(lines, t("section.next_actions", "NEXT STEPS"))
        actions = result.next_actions
        actions = actions.select { |action| action.priority <= 3 }.first(2) unless @options.verbose

        actions.each_with_index do |action, index|
          label = action.label
          if action.authorized && !label.match?(/authorized|已授权/i)
            label += " #{t('next_actions.authorized_tag', '[authorized]')}"
          end
          hung(lines, "    #{@paint.call((index + 1).to_s, :bold)}. ", label)

          command_lines = Layout.wrap(Sanitize.terminal(action.command), Layout.width - 10)
          lines << "       #{@paint.call('$', :dim)} #{command_lines.shift}"
          command_lines.each { |line| lines << "         #{line}" }

          if @options.verbose && action.why && !action.why.empty?
            hung(lines, "       ", "#{t('next_actions.why', 'why:')} #{action.why}")
          end
        end
      end

      def remediation_section(lines, result)
        section(lines, t("section.remediation", "HOW TO FIX IT"))
        result.remediation.each { |step| hung(lines, "    - ", step) }
      end

      def run_summary(lines)
        s = @summary
        section(lines, t("section.run_summary", "RUN SUMMARY"))

        if @options.verbose
          summary_field(lines, t("summary.targets", "targets"),
                        t("summary.targets_value",
                          "%{total} (exposed %{exposed}, patched %{patched}, no PHP %{no_php})",
                          total: s[:total], exposed: s[:exposed], patched: s[:patched], no_php: s[:no_php]))
          unverified = s[:unverified].to_s
          reasons = unverified_reasons
          unverified += t("summary.reasons", " (%{reasons})", reasons: reasons) unless reasons.empty?
          summary_field(lines, t("summary.unverified", "unverified"), unverified)
          summary_field(lines, t("summary.errors", "errors"), s[:errors].to_s)
          summary_field(lines, t("summary.coverage", "coverage"),
                        t("summary.coverage_value",
                          "%{usable}/%{attempted} probes usable (%{percent}%) · " \
                          "%{assessable}/%{total} targets assessable",
                          usable: s[:coverage][:usable], attempted: s[:coverage][:attempted],
                          percent: format('%.1f', s[:coverage][:percent]),
                          assessable: s[:assessable], total: s[:total]))
        else
          summary_field(lines, t("summary.checked", "checked"),
                        t("summary.checked_value",
                          "%{total} %{host_word}: %{hackable} hackable, %{not_hackable} not hackable, " \
                          "%{unknown} could not be checked",
                          total: s[:total],
                          host_word: s[:total] == 1 ? t("common.host", "host") : t("common.hosts", "hosts"),
                          hackable: s[:hackable], not_hackable: s[:not_hackable],
                          unknown: s[:decision_unknown]))
          summary_field(lines, t("summary.errors", "errors"), s[:errors].to_s) if s[:errors].positive?
        end

        summary_field(lines, t("summary.requests", "requests"),
                      t("summary.requests_value", "%{requests} in %{duration}",
                        requests: s[:requests], duration: format_duration(s[:duration_ms])))
        if s[:scope_skipped].positive?
          summary_field(lines, t("summary.scope", "scope"),
                        t("summary.scope_value", "%{count} skipped outside scope", count: s[:scope_skipped]))
        end
      end

      # Only advertise what the reader has not already turned on. Repeating
      # "-v gives detail" to someone who just ran -v is noise.
      def tip(lines)
        hints = []
        hints << t("tip.verbose", "-v for technical details") unless @options.verbose
        hints << t("tip.toolchain", "-c for tools") unless @options.toolchain
        hints << t("tip.redteam", "-r for attacker notes") unless @options.redteam
        hints << t("tip.quiet", "-q for the short version") unless @options.quiet

        parts = []
        parts << "--format json|markdown|sarif|csv|ndjson"
        parts << "--dry-run"
        parts << t("tip.exit_codes", "exit codes 0/1/2/3/4")

        blank(lines)
        label = t("tip.label", "  Tip: ")
        period = t("tip.sentence_end", ".")
        if hints.empty?
          styled_hung(lines, label, "#{parts.join(' · ')}#{period}", :dim)
        else
          styled_hung(lines, label, "#{hints.join(' · ')}#{period}", :dim)
          styled_hung(lines, " " * Layout.display_width(label), "#{parts.join(' · ')}#{period}", :dim)
        end
      end

      # -- helpers ----------------------------------------------------------

      def section(lines, title)
        blank(lines)
        lines << @paint.call("  #{title}", :bold, :cyan)
      end

      def blank(lines)
        lines << "" unless lines.empty? || lines.last == ""
      end

      def field(lines, label, value, width: 11)
        prefix = "  #{label}#{t('common.colon', ':')}"
        prefix = Layout.pad(prefix, [width + 4, Layout.display_width(prefix) + 1].max)
        styled_hung(lines, prefix, Sanitize.terminal(value), :dim)
      end

      # Run-summary labels are a little shorter than the assessment table's
      # widest label ("Hackability"), so use their own width to keep the
      # stable "unverified: N" string aligned and greppable.
      def summary_field(lines, label, value)
        field(lines, label, value, width: 10)
      end

      def hung(lines, prefix, text, hang: nil)
        Layout.wrap_hanging(prefix, Sanitize.terminal(text), hang || Layout.display_width(prefix))
              .each { |line| lines << line }
      end

      # Wrap with a plain prefix (so layout maths are exact), then colour the
      # prefix in the first emitted line. Colouring before layout would count
      # escape bytes as visible columns and wrap too early.
      def styled_hung(lines, prefix, text, *styles)
        Layout.wrap_hanging(prefix, Sanitize.terminal(text), Layout.display_width(prefix))
              .each_with_index do |line, index|
          lines << if index.zero? && !styles.empty?
                     @paint.call(prefix, *styles) + line[prefix.length..].to_s
                   else
                     line
                   end
        end
      end

      def present?(value)
        !value.nil? && !value.to_s.strip.empty? && value.to_s != "none"
      end

      def verdict_cell(result)
        paint_verdict(verdict_label(result.verdict), result.verdict.status)
      end

      def paint_verdict(label, status)
        @paint.call(label, *Style::VERDICT_COLOURS.fetch(status, []))
      end

      def access_cell(result)
        state = result.verdict.access&.state
        @paint.call(access_code(state), *Style::ACCESS_COLOURS.fetch(state, []))
      end

      def access_detail(access)
        return t("common.unknown", "unknown") unless access

        label = access_label(access.state)
        status = access.control && access.control[:status]
        status = nil unless %i[blocked restricted server_error].include?(access.state)
        status ? t("access.detail_http", "%{label} (HTTP %{status})", label: label, status: status) : label
      end

      def blocked_page
        @results.filter_map do |result|
          result.environment.block_page if result.verdict.reason_code == :blocked
        end.find(&:ua_sensitive)
      end

      def unverified_reasons
        s = @summary
        reasons = []
        reasons << t("summary.reason.blocked", "blocked %{count}", count: s[:blocked]) if s[:blocked].positive?
        reasons << t("summary.reason.auth_wall", "auth wall %{count}", count: s[:auth_wall]) if s[:auth_wall].positive?
        reasons << t("summary.reason.rate_limited", "rate limited %{count}", count: s[:rate_limited]) if s[:rate_limited].positive?
        reasons << t("summary.reason.soft_404", "soft-404 %{count}", count: s[:soft_404]) if s[:soft_404].positive?
        reasons << t("summary.reason.unreachable", "unreachable %{count}", count: s[:unreachable]) if s[:unreachable].positive?
        reasons << t("summary.reason.unknown", "unknown version %{count}", count: s[:unknown]) if s[:unknown].positive?
        reasons.join(t("common.list_separator", ", "))
      end

      def verdict_label(verdict)
        status = verdict.status
        t("verdict.#{status}", VERDICT_LABEL.fetch(status, "?"))
      end

      def access_code(state)
        t("access.code.#{state}", ACCESS_CODE.fetch(state, "?"))
      end

      def access_label(state)
        t("access.label.#{state}", ACCESS_LABEL.fetch(state, "unknown"))
      end

      def risk_cell(result)
        score = result.risk[:score]
        return @paint.call(t("common.na", "n/a"), :dim) if score.nil?

        text = "#{format('%.1f', score)} #{grade_label(result.risk[:grade])}"
        styles = if score >= 7.0
                   %i[bold red]
                 elsif score >= 4.0
                   %i[bold yellow]
                 else
                   [:green]
                 end
        @paint.call(text, *styles)
      end

      def risk_text(result)
        score = result.risk[:score]
        grade = grade_label(result.risk[:grade])
        return t("risk.na", "n/a (%{grade})", grade: grade) if score.nil?

        t("risk.value", "%{score}/10 (%{grade})", score: format('%.1f', score), grade: grade)
      end

      def evidence_cell(result)
        coverage = result.fingerprint[:coverage] || {}
        "#{coverage[:usable].to_i}/#{coverage[:attempted].to_i}"
      end

      def version_cell(verdict)
        unless verdict.version
          return t("plain.version_hidden", "present, version hidden") if verdict.attack_surface[:php_detected]

          return t("plain.version_none", "not seen")
        end

        version_short(verdict)
      end

      def version_short(verdict)
        return t("common.unknown", "unknown") unless verdict.version

        text = verdict.version.to_s
        text += " #{t('version.branch', '(branch)')}" if verdict.version_precision == :minor
        text
      end

      def version_table_text(verdict)
        return t("common.unknown", "unknown") unless verdict.version

        text = verdict.version.to_s
        text += " #{t('version.branch', '(branch)')}" if verdict.version_precision == :minor
        text += t("version.floor", " · floor %{floor}", floor: verdict.fix_floor) if verdict.fix_floor
        text
      end

      def paint_answer(result)
        rating = result.hackability.rating
        tone = case rating
               when :exposed, :likely then :red
               when :not_exposed then :green
               else :yellow
               end
        @paint.call(answer_word(rating), :bold, tone)
      end

      def result_word(rating)
        case rating
        when :exposed, :likely then t("plain.result_hackable", "HACKABLE")
        when :not_exposed then t("plain.result_not_hackable", "NOT HACKABLE")
        else t("plain.result_unknown", "UNKNOWN")
        end
      end

      def plain_reason(result)
        v = result.verdict
        case v.reason_code
        when :vulnerable
          t("plain.reason.vulnerable", "The PHP version is older than the fixed release for this bug.")
        when :eol
          t("plain.reason.eol", "The PHP branch is no longer supported, so no fix is coming.")
        when :patched
          t("plain.reason.patched", "The PHP version is at or above the fixed release.")
        when :no_php
          t("plain.reason.no_php", "No PHP was found on the pages tested.")
        when :no_version
          t("plain.reason.no_version", "PHP was detected, but the version was not exposed.")
        when :branch_only
          t("plain.reason.branch_only", "Only the PHP branch was exposed, not the patch version.")
        when :newer_than_table
          t("plain.reason.newer_than_table", "The PHP branch is newer than this tool's fix table.")
        when :blocked
          t("plain.reason.blocked", "The edge blocked the scan before it reached the application.")
        when :restricted
          t("plain.reason.restricted", "The main page is protected, so the scan could not see the application.")
        when :auth_wall
          t("plain.reason.auth_wall", "The site requires a login before showing the application.")
        when :rate_limited
          t("plain.reason.rate_limited", "The site rate-limited the scan.")
        when :soft_404
          t("plain.reason.soft_404", "The site returns the same page for every path, so page results cannot be trusted.")
        when :server_error
          t("plain.reason.server_error", "The site returned a server error during the scan.")
        when :unreachable
          t("plain.reason.unreachable", "The site did not respond.")
        else
          v.reason
        end
      end

      def note_text(result)
        v = result.verdict

        # A version that leaked through a block page is still a version. Put
        # the patch conclusion first; the block is secondary context.
        case v.status
        when :vulnerable then return t("note.vulnerable", "below %{floor}", floor: v.fix_floor)
        when :eol then return t("note.eol", "end-of-life branch")
        when :patched then return t("note.patched", "patched")
        when :no_php then return t("note.no_php", "no PHP seen")
        end

        if (block_page = result.environment.block_page)
          return t("note.blocked_by", "blocked by %{vendor}", vendor: block_page.vendor) if block_page.vendor

          return t("note.blocked", "blocked at the edge")
        end

        case v.reason_code
        when :branch_only then t("note.branch_only", "version not shown")
        when :newer_than_table then t("note.newer_than_table", "newer PHP branch")
        when :no_version then t("note.no_version", "version not shown")
        when :auth_wall then t("note.auth_wall", "login required")
        when :rate_limited then t("note.rate_limited", "rate limited")
        when :soft_404 then t("note.soft_404", "catch-all pages")
        when :server_error then t("note.server_error", "server error")
        when :unreachable then t("note.unreachable", "unreachable")
        when :restricted then t("note.restricted", "restricted path")
        when :blocked then t("note.blocked", "blocked at the edge")
        else v.reason_code.to_s.tr("_", " ")
        end
      end

      def confidence_plain(verdict)
        return t("plain.confidence_none", "Low — the PHP version was not visible.") unless verdict.version

        if verdict.access && !verdict.access.open?
          return t("plain.confidence_blocked", "Low — the version came from a blocked response.")
        end
        if verdict.version_precision == :minor
          return t("plain.confidence_branch", "Low — only the branch was shown, not the patch version.")
        end

        key = verdict.confidence.to_s
        t("plain.confidence_#{key}",
          case key
          when "high" then "High — the version came from a response header."
          when "medium" then "Medium — the version came from application output."
          else "Low — the version was inferred."
          end)
      end

      def coverage_plain(result)
        coverage = result.fingerprint[:coverage] || {}
        attempted = coverage[:attempted].to_i
        usable = coverage[:usable].to_i
        return t("plain.coverage_none", "No pages were checked.") if attempted.zero?

        t("plain.coverage", "%{usable} of %{attempted} pages responded normally",
          usable: usable, attempted: attempted)
      end

      def version_plain(verdict)
        unless verdict.version
          return t("plain.version_hidden", "present, version hidden") if verdict.attack_surface[:php_detected]

          return t("plain.version_none", "not seen")
        end

        text = verdict.version.to_s
        text += " #{t('version.branch', '(branch only)')}" if verdict.version_precision == :minor
        source = version_source_plain(verdict.version_source)
        source ? "#{text} — #{source}" : text
      end

      def version_source_plain(source)
        return nil if source.nil? || source.to_s.empty?

        text = source.to_s
        if text.match?(/header/i)
          t("plain.source_header", "from a response header")
        elsif text.match?(/phpinfo/i)
          t("plain.source_phpinfo", "from phpinfo()")
        else
          Sanitize.terminal(text)
        end
      end

      def fix_text(verdict)
        return nil unless verdict.exposed?

        if verdict.status == :vulnerable
          t("plain.fix_vulnerable", "Upgrade PHP to %{floor} or later.", floor: verdict.fix_floor)
        else
          floors = Verdict::FIXED_RELEASES.values.map(&:to_s).join(", ")
          t("plain.fix_eol",
            "Upgrade to a supported PHP branch (%{floors}) or your distro's fixed package.",
            floors: floors)
        end
      end

      def hackability_text(h)
        ratio = h.ratio.nil? ? t("common.na", "n/a") : format("%.2f", h.ratio)
        t("technical.hackability_value", "%{answer} — %{label} (ratio %{ratio})",
          answer: answer_word(h.rating), label: hackability_label(h.rating), ratio: ratio)
      end

      def control_text(access)
        return t("common.none", "none") unless access&.control

        status = access.control[:status] || t("common.error", "error")
        similarity = access.control[:similarity]
        if similarity
          t("assessment.control_similarity", "%{status} (similarity %{similarity})",
            status: status, similarity: format('%.2f', similarity))
        else
          status.to_s
        end
      end

      def friction_text(result)
        friction = result.risk[:friction]
        return t("common.na", "n/a") unless friction && !friction[:factors].empty?

        factors = friction[:factors].map { |factor| friction_factor_label(factor[:factor]) }
                         .uniq.join(t("common.list_separator", ", "))
        t("assessment.friction_value", "%{level} (%{factors})",
          level: friction_level_label(friction[:level]), factors: factors)
      end

      def confidence_label(value)
        key = value.to_s.downcase
        t("confidence.#{key}", value.to_s)
      end

      def grade_label(grade)
        key = grade.to_s.downcase
        t("grade.#{key}", grade.to_s)
      end

      def hackability_label(rating)
        t("hackability.#{rating}", Hackability::RATINGS.fetch(rating, rating.to_s))
      end

      # The decision vocabulary: exposed/likely answer YES, not-exposed
      # answers NO, everything unverified answers UNKNOWN rather than
      # pretending either way.
      def answer_word(rating)
        case rating
        when :exposed, :likely then t("decision.yes", "YES")
        when :not_exposed then t("decision.no", "NO")
        else t("decision.unknown", "UNKNOWN")
        end
      end

      # SAPI values stay canonical in the data model because risk.rb and the
      # remediation branches match on them. Only the display label moves.
      def sapi_label(value)
        key = {
          "mod_php (likely)" => "mod_php_likely",
          "mod_php (possible)" => "mod_php_possible",
          "php-fpm (likely)" => "php_fpm_likely",
          "php-fpm (possible)" => "php_fpm_possible",
          "php-cgi (possible)" => "php_cgi_possible",
          "litespeed" => "litespeed"
        }[value.to_s]
        key ? t("sapi.#{key}", value.to_s) : t("common.unknown", "unknown")
      end

      def edge_text(value)
        key = value.to_s.tr(" ", "_")
        default = { "ovhcloud" => "OVHcloud" }.fetch(value.to_s, value.to_s)
        t("edge.#{key}", default)
      end

      def tactic_label(tactic)
        key = tactic.to_s.downcase.gsub(/[^a-z0-9]+/, "_").sub(/\A_+|_+\z/, "")
        t("tactic.#{key}", tactic.to_s)
      end

      def phase_label(phase)
        key = phase.to_s.downcase.gsub(/[^a-z0-9]+/, "_").sub(/\A_+|_+\z/, "")
        t("phase.#{key}", phase.to_s)
      end

      def friction_factor_label(factor)
        key = factor.to_s
        t("friction_factor.#{key}", key.tr("_", " "))
      end

      def friction_level_label(level)
        key = level.to_s
        t("friction_level.#{key}", key)
      end

      def surface_text(surface, verdict)
        t("surface.value",
          "PHP %{php} · phpinfo %{phpinfo} · live .php %{live} · upload %{upload} · errors %{errors}",
          php: surface_bool(surface[:php_detected], verdict),
          phpinfo: surface_bool(surface[:phpinfo_exposed], verdict),
          live: surface_bool(surface[:php_paths_live], verdict),
          upload: surface_bool(surface[:upload_progress], verdict),
          errors: surface_bool(surface[:php_errors], verdict))
      end

      # "no" and "not observed" are different claims. A blocked host did not
      # prove that PHP is absent; it only proved that the scanner could not
      # see it.
      def surface_bool(value, verdict)
        return t("bool.yes", "yes") if value
        return t("bool.not_observed", "not observed") if verdict.unverified?

        t("bool.no", "no")
      end

      def block_page_text(block_page)
        return t("common.none", "none") unless block_page

        [block_page.vendor, block_page.summary].compact.reject(&:empty?)
                                                .join(t("common.detail_separator", "; "))
      end

      def framework_text(environment)
        environment.frameworks.map do |framework|
          t("framework.entry", "%{name} (%{confidence})",
            name: framework.name, confidence: confidence_label(framework.confidence))
        end.join(t("common.list_separator", ", "))
      end

      def probe_signal(probe)
        return t("probe.control", "control") if probe.purpose.to_s.start_with?("control")
        return t("probe.discovery", "discovery") if probe.purpose.to_s.start_with?("discovery")
        return probe_error_label(probe.error_kind) if probe.error?
        return t("probe.denied", "denied") if probe.denied?
        return t("probe.rate_limited", "rate limited") if probe.rate_limited?
        return t("probe.not_found", "not found") if probe.not_found?
        return t("probe.server_error", "server error") if probe.server_error?
        return t("probe.redirect", "redirect") if probe.redirect?

        markers = probe.php_markers.map { |marker| marker_label(marker[:kind].to_s) }
        markers << t("probe.phpinfo", "phpinfo") if probe.phpinfo?
        markers << t("probe.fpm_not_found", "fpm-404") if probe.php_fpm_not_found?
        return markers.uniq.join(",") unless markers.empty?

        t("probe.ok", "ok")
      end

      def probe_error_label(kind)
        key = kind.to_s
        t("probe.error.#{key}", key)
      end

      def marker_label(kind)
        key = kind.to_s.tr("_", "-")
        t("probe.marker.#{key}", key)
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
