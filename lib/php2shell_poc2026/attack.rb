# frozen_string_literal: true

module PHP2ShellPOC2026
  # ATT&CK coverage for the PHP2Shell kill chain. Both CVEs fire during
  # request parsing, before a single line of application code runs, so the
  # whole chain lives in the narrow gap between "we sent an HTTP request" and
  # "a web worker is running someone else's shell" — the notes say as much,
  # because that gap is exactly where app-layer controls (auth, IAM, SSO)
  # stop applying.
  module Attack
    Technique = Struct.new(:id, :name, :tactic, :applies, :note, keyword_init: true)

    def self.techniques_for(verdict)
      return [] unless verdict.exposed?

      [
        Technique.new(
          id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access",
          applies: "unauthenticated",
          note: "One crafted HTTP request reaches the PHP parser before any application code runs; " \
                "app-layer authentication, IAM or SSO cannot block it."
        ),
        Technique.new(
          id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell", tactic: "Execution",
          applies: "RCE",
          note: "Confirmed exploit paths execute attacker commands as the web worker (www-data/apache/nginx)."
        ),
        Technique.new(
          id: "T1505.003", name: "Server Software Component: Web Shell", tactic: "Persistence",
          applies: "RCE",
          note: "Landing inside a long-lived worker (mod_php/FPM) makes a persistent webshell drop trivial; " \
                "successful execution need not crash or restart the worker, so it stays quiet."
        ),
        Technique.new(
          id: "T1005", name: "Data from Local System", tactic: "Collection",
          applies: "memory disclosure",
          note: "The disclosure variant leaks process memory (Heartbleed-style): env vars, cloud keys, " \
                "session material — reachable without achieving code execution."
        ),
        Technique.new(
          id: "T1082", name: "System Information Discovery", tactic: "Discovery",
          applies: "post-exploitation",
          note: "Recon through the hijacked interpreter looks exactly like ordinary app traffic without EDR."
        ),
        Technique.new(
          id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control",
          applies: "post-exploitation",
          note: "C2 and exfil blend into normal HTTPS egress from the web tier."
        )
      ]
    end
  end
end
