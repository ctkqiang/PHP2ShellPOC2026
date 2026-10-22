# frozen_string_literal: true

module PHP2ShellPOC2026
  # The adversary's-eye view of this specific finding — short, opinionated
  # paragraphs an operator can act on during scoping. Kept separate from
  # Tooling: this answers "how would someone attack *this host*", that one
  # answers "what equipment does a team bring".
  module RedTeam
    def self.notes(verdict, environment)
      return [] unless verdict.exposed?

      notes = [
        "Any .php endpoint is a valid entry point — on a WordPress-style portal that is guaranteed " \
        "(wp-login.php, xmlrpc.php, wp-cron.php). No valid credentials or session needed.",
        "mod_php is the highest-risk posture per the PHP project: one request, one process, no worker recycle " \
        "between victims. FPM lowers odds (both requests must hit the same worker) but does not remove them."
      ]

      if verdict.status == :eol
        notes << "EOL PHP (<= 8.1): no upstream fix exists. Defenders can only rely on backports, config " \
                 "mitigations or network isolation — expect this class of target to be prioritised by attackers."
      end

      if environment.cdn?
        notes << "CDN in front (#{environment.cdn}): WAF rules protect the front door only. If the origin IP leaks " \
                 "(old DNS records, mail headers, certs on censys/shodan), direct-to-origin traffic skips every control."
      end

      notes << "Opsec: the memory-disclosure variant leaks data without crashing the worker, so availability " \
               "monitoring alone will not reveal the probing phase. Exploitation attempts may look like ordinary " \
               "large form submissions."
      notes
    end
  end
end
