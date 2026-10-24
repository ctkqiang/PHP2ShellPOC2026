# frozen_string_literal: true

module PHP2ShellPOC2026
  # ATT&CK on two levels, because a passive scan is itself an ATT&CK
  # activity:
  #
  # * assessment_path — the Reconnaissance techniques this scan performed
  #   and the next low-risk verification steps. It is always present, so a
  #   blocked or patched target does not produce an empty section.
  # * kill_chain — the techniques that would apply only if a vulnerable
  #   interpreter were actually confirmed. It is deliberately empty
  #   otherwise; printing a kill chain for an unconfirmed finding trains
  #   people to ignore it.
  module Attack
    Technique = Struct.new(:id, :name, :tactic, :phase, :applies, :note, :url,
                           keyword_init: true) do
      def to_h
        {
          id: id, name: name, tactic: tactic, phase: phase,
          applies: applies, note: note, url: url
        }
      end
    end

    ATTACK_URL = "https://attack.mitre.org/techniques/%s/"

    def self.kill_chain(verdict)
      return [] unless verdict.exposed?

      [
        technique("T1190", "Exploit Public-Facing Application", "Initial Access", "kill_chain",
                  "unauthenticated",
                  "One crafted HTTP request reaches the PHP parser before any application code runs; " \
                  "app-layer authentication, IAM or SSO cannot block it."),
        technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "kill_chain",
                  "RCE",
                  "Confirmed exploit paths execute attacker commands as the web worker (www-data/apache/nginx)."),
        technique("T1505.003", "Server Software Component: Web Shell", "Persistence", "kill_chain",
                  "RCE",
                  "Landing inside a long-lived worker (mod_php/FPM) makes a persistent webshell drop trivial; " \
                  "successful execution need not crash or restart the worker, so it stays quiet."),
        technique("T1005", "Data from Local System", "Collection", "kill_chain",
                  "memory disclosure",
                  "The disclosure variant leaks process memory (Heartbleed-style): env vars, cloud keys, " \
                  "session material — reachable without achieving code execution."),
        technique("T1082", "System Information Discovery", "Discovery", "kill_chain",
                  "post-exploitation",
                  "Recon through the hijacked interpreter looks like ordinary app traffic without EDR."),
        technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "kill_chain",
                  "post-exploitation",
                  "C2 and exfil blend into normal HTTPS egress from the web tier.")
      ]
    end

    def self.assessment_path(verdict, environment, requests: nil, profile: nil)
      path = []
      path << technique(
        "T1595", "Active Scanning", "Reconnaissance", "assessment", "this scan",
        "#{requests || 'A small number of'} ordinary GET requests#{profile ? " (#{profile} profile)" : ''}; " \
        "no payloads, no state-changing verbs, no exploitation. This scan is visible in web logs."
      )
      path << technique(
        "T1592", "Gather Victim Host Information", "Reconnaissance", "assessment", "this scan",
        "Response headers, TLS certificate, server/edge fingerprint, cookies and framework markers were read " \
        "passively to identify the deployment."
      )

      if environment.cdn?
        path << technique(
          "T1596", "Search Open Technical Databases", "Reconnaissance", "assessment", "next step",
          "Certificate transparency, historical DNS and internet-wide scan data can reveal the origin behind " \
          "#{environment.cdn}; direct-to-origin traffic bypasses edge rules."
        )
        path << technique(
          "T1590", "Gather Victim Network Information", "Reconnaissance", "assessment", "next step",
          "Map the origin's network position and confirm it only accepts traffic from the CDN range."
        )
      elsif verdict.unverified?
        path << technique(
          "T1596", "Search Open Technical Databases", "Reconnaissance", "assessment", "next step",
          "Use certificate transparency, DNS history and Shodan/Censys to corroborate the host and find side " \
          "assets that expose the same interpreter."
        )
      end

      if verdict.no_php?
        path << technique(
          "T1046", "Network Service Discovery", "Discovery", "assessment", "next step (authorized)",
          "No PHP was observed on this route; an authorized port/service scan may find other web tiers or " \
          "development servers that do run PHP."
        )
      end

      if verdict.unverified?
        path << technique(
          "T1592", "Gather Victim Host Information", "Reconnaissance", "assessment", "next step",
          "The edge denied or obscured the application. Verify the interpreter host-side, or from an approved " \
          "egress/proxy, before treating the target as patched."
        )
      end

      path
    end

    def self.technique(id, name, tactic, phase, applies, note)
      Technique.new(id: id, name: name, tactic: tactic, phase: phase, applies: applies,
                    note: note, url: attack_url(id))
    end

    def self.attack_url(id)
      path = id.to_s.tr(".", "/")
      format(ATTACK_URL, path)
    end
  end
end
