# frozen_string_literal: true

require "json"

require_relative "../version"

module PHP2ShellPOC2026
  module Report
    # SARIF 2.1.0 for code-scanning and security dashboards. Exposed targets
    # are errors; blocked/unverified targets are notes, because the honest
    # answer to a blanket 403 is "go look", not "clean". Patched and no-PHP
    # targets are represented in the invocation summary, not as findings.
    module Sarif
      SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

      RULES = [
        {
          id: "PHP2Shell.VulnerableInterpreter",
          name: "Vulnerable PHP interpreter",
          shortDescription: { text: "PHP interpreter is below the branch fix level for the PHP2Shell bug class." },
          fullDescription: { text: "The observed PHP version predates the first fixed release on its branch. " \
                                   "CVE-2026-109618 and CVE-2026-109619 are parser-level issues that fire before " \
                                   "application authentication or routing." },
          helpUri: "https://github.com/ctkqiang/PHP2ShellPOC2026",
          defaultConfiguration: { level: "error" },
          properties: { tags: ["security", "php", "CVE-2026-109618", "CVE-2026-109619"] }
        },
        {
          id: "PHP2Shell.EndOfLifeInterpreter",
          name: "End-of-life PHP interpreter",
          shortDescription: { text: "PHP branch is end-of-life and has no upstream fix for this bug class." },
          fullDescription: { text: "The observed PHP branch is outside the supported fix table. A distro backport " \
                                   "or an upgrade is required; the upstream branch never received the fix." },
          helpUri: "https://github.com/ctkqiang/PHP2ShellPOC2026",
          defaultConfiguration: { level: "error" },
          properties: { tags: ["security", "php", "end-of-life"] }
        },
        {
          id: "PHP2Shell.Unverified",
          name: "PHP exposure unverified",
          shortDescription: { text: "The scan could not observe the interpreter (blocked, auth wall, soft-404 or no version)." },
          fullDescription: { text: "No positive or negative evidence about the interpreter was available. " \
                                   "This is not a clean result: verify host-side or from an approved vantage point." },
          helpUri: "https://github.com/ctkqiang/PHP2ShellPOC2026",
          defaultConfiguration: { level: "note" },
          properties: { tags: ["security", "php", "needs-review"] }
        }
      ].freeze

      def self.render(results, _options, summary:, meta: {})
        findings = results.select { |result| result.exposed? || result.unverified? }
        payload = {
          "$schema" => SCHEMA,
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "php2shell-poc2026",
                  informationUri: HOMEPAGE,
                  version: VERSION,
                  rules: RULES
                }
              },
              automationDetails: { id: "php2shell-poc2026/#{meta[:generated_at] || Time.now.utc.iso8601}" },
              originalUriBaseIds: {
                "SRCROOT" => { uri: "file:///" }
              },
              artifacts: results.map do |result|
                {
                  location: { uri: result.target.uri.to_s },
                  roles: ["analysisTarget"],
                  properties: {
                    target: result.target.display,
                    scheme: result.target.scheme,
                    host: result.target.ascii_host,
                    port: result.target.port
                  }
                }
              end,
              invocations: [
                {
                  executionSuccessful: results.none? { |result| result.error },
                  endTimeUtc: meta[:generated_at] || Time.now.utc.iso8601,
                  properties: {
                    profile: meta[:profile],
                    targets: summary[:total],
                    exposed: summary[:exposed],
                    patched: summary[:patched],
                    no_php: summary[:no_php],
                    unverified: summary[:unverified],
                    hackable: summary[:hackable],
                    not_hackable: summary[:not_hackable],
                    decision_unknown: summary[:decision_unknown],
                    requests: summary[:requests],
                    coverage: summary[:coverage]
                  }
                }
              ],
              results: findings.map { |result| finding(result) },
              properties: {
                summary: summary,
                tool: { name: "php2shell-poc2026", version: VERSION }
              }
            }
          ]
        }
        JSON.pretty_generate(payload) + "\n"
      end

      def self.finding(result)
        v = result.verdict
        rule_id = rule_for(v)
        level = if v.exposed? then "error" elsif v.unverified? then "note" else "none" end
        {
          ruleId: rule_id,
          ruleIndex: RULES.index { |rule| rule[:id] == rule_id } || 2,
          level: level,
          message: { text: message_for(result) },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: result.target.uri.to_s },
                region: { startLine: 1, startColumn: 1 }
              }
            }
          ],
          properties: {
            target: result.target.display,
            verdict: v.status,
            reason_code: v.reason_code,
            version: v.version&.to_s,
            branch: v.branch,
            fix_floor: v.fix_floor&.to_s,
            confidence: v.confidence,
            risk_score: result.risk[:score],
            risk_grade: result.risk[:grade],
            hackable: result.hackability.hackable?,
            answer: result.hackability.answer.to_s,
            decision_action: result.hackability.action,
            access_state: v.access&.state,
            access_reason: v.access&.reason,
            server: result.environment.server,
            edge: result.environment.edge,
            cdn: result.environment.cdn,
            waf: result.environment.waf,
            sapi: result.environment.sapi,
            requests: result.meta[:requests],
            coverage: result.fingerprint[:coverage]
          }
        }
      end

      def self.rule_for(verdict)
        return "PHP2Shell.VulnerableInterpreter" if verdict.status == :vulnerable
        return "PHP2Shell.EndOfLifeInterpreter" if verdict.status == :eol

        "PHP2Shell.Unverified"
      end

      def self.message_for(result)
        v = result.verdict
        h = result.hackability
        answer = h.answer.to_s.upcase
        if v.exposed?
          "#{result.target.display}: PHP2Shell decision #{answer} — #{v.reason} " \
            "(risk #{result.risk[:score]}/10, confidence #{v.confidence}). Action: #{h.action}."
        else
          "#{result.target.display}: PHP2Shell decision #{answer} — exposure unverified: #{v.reason} " \
            "Do not treat this as a clean result; verify host-side or from an approved vantage point."
        end
      end
    end
  end
end
