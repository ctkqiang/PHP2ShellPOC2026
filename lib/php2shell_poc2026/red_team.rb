# frozen_string_literal: true

module PHP2ShellPOC2026
  # The adversary's-eye view of this specific finding — short, opinionated
  # paragraphs an operator can act on during scoping. Kept separate from
  # Tooling: this answers "how would someone attack *this host*", that one
  # answers "what equipment does a team bring".
  module RedTeam
    def self.notes(verdict, environment)
      if verdict.exposed?
        exposed_notes(verdict, environment)
      elsif verdict.unverified?
        unverified_notes(verdict, environment)
      elsif verdict.patched?
        patched_notes
      else
        no_php_notes
      end
    end

    def self.exposed_notes(verdict, environment)
      notes = [
        "The request parser runs before application code, so every .php route is an entry point — no " \
        "credentials, session or user interaction required."
      ]

      framework = verdict.attack_surface[:framework]
      if framework == "WordPress"
        notes << "WordPress is confirmed here: wp-login.php, xmlrpc.php and /wp-json/ are guaranteed .php " \
                 "routes, and the parser bug does not care which one you pick."
      elsif framework
        notes << "#{framework} is confirmed here; its standard .php endpoints are additional entry points."
      end

      notes << "mod_php is the highest-risk posture per the PHP project: one request, one process, no worker " \
               "recycle between victims. FPM lowers odds (both requests must hit the same worker) but does not " \
               "remove them."

      if verdict.status == :eol
        notes << "EOL PHP (#{verdict.version}, branch #{verdict.branch}): no upstream fix exists. Defenders can " \
                 "only rely on backports, config mitigations or network isolation — expect this class of target " \
                 "to be prioritised by attackers."
      end

      if environment.waf
        notes << "WAF fingerprint: #{environment.waf}. That changes exploit reliability, not exposure — the " \
                 "interpreter is still unpatched behind it. Finding the origin is usually the cheaper path."
      end

      if environment.cdn?
        notes << "CDN in front (#{environment.cdn}): WAF rules protect the front door only. If the origin IP " \
                 "leaks (old DNS records, mail headers, certs on Censys/Shodan), direct-to-origin traffic skips " \
                 "every control."
      end

      notes << "Opsec: the memory-disclosure variant leaks data without crashing the worker, so availability " \
               "monitoring alone will not reveal the probing phase. Exploitation attempts may look like ordinary " \
               "large form submissions."
      notes
    end

    def self.unverified_notes(verdict, environment)
      notes = []
      if verdict.access&.blocked?
        notes << "A 403 is an observation about the edge, not about the interpreter. Attackers will try other " \
                 "egress, other hostnames, or the origin before concluding anything."
      elsif verdict.access&.state == :auth_wall
        notes << "The login wall does not close this bug class: the parser runs before authentication. It does " \
                 "mean the reachable surface is narrower until credentials (or an authorized authenticated test) " \
                 "exist."
      elsif verdict.access&.state == :soft_404
        notes << "Catch-all routing makes path fuzzing useless here; attackers will pivot to header/cookie " \
                 "evidence and host-side fingerprinting instead."
      else
        notes << "No usable application response was obtained. Treat the host as unassessed and verify from " \
                 "another vantage point before drawing a conclusion."
      end

      notes << "The random canary path this scanner requests is a detectable signature; a defender watching " \
               "for it can distinguish reconnaissance from normal traffic."
      notes << "Origin discovery is the next step if a CDN is present: certificate transparency, historical DNS, " \
               "and internet-wide scan data often expose the real host." if environment.cdn?
      notes << "If a WAF is present (#{environment.waf}), do not assume it covers this CVE — presence is not " \
               "rule coverage." if environment.waf && environment.waf != "unidentified edge control"
      notes
    end

    def self.patched_notes
      [
        "No kill chain for this bug class: the interpreter meets the fix level. Pivot to application-layer " \
        "bugs, framework/plugin versions and misconfiguration.",
        "A patched flagship host says nothing about sibling subdomains, staging boxes or forgotten vhosts; " \
        "that is where the same branch usually survives."
      ]
    end

    def self.no_php_notes
      [
        "No PHP was observed on the tested routes. Check other vhosts, ports and applications before treating " \
        "the estate as PHP-free.",
        "A static front end can hide a PHP admin or API behind a different Host header or path."
      ]
    end
  end
end
