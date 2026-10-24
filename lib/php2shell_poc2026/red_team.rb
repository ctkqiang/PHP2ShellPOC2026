# frozen_string_literal: true

require_relative "i18n"

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
        t("data.red_team.exposed.parser",
          "The request parser runs before application code, so every .php route is an entry point — no " \
          "credentials, session or user interaction required.")
      ]

      framework = verdict.attack_surface[:framework]
      if framework == "WordPress"
        notes << t("data.red_team.exposed.wordpress",
                   "WordPress is confirmed here: wp-login.php, xmlrpc.php and /wp-json/ are guaranteed .php " \
                   "routes, and the parser bug does not care which one you pick.")
      elsif framework
        notes << t("data.red_team.exposed.framework",
                   "%{framework} is confirmed here; its standard .php endpoints are additional entry points.",
                   framework: framework)
      end

      notes << t("data.red_team.exposed.sapi",
                 "mod_php is the highest-risk posture per the PHP project: one request, one process, no worker " \
                 "recycle between victims. FPM lowers odds (both requests must hit the same worker) but does not " \
                 "remove them.")

      if verdict.status == :eol
        notes << t("data.red_team.exposed.eol",
                   "EOL PHP (%{version}, branch %{branch}): no upstream fix exists. Defenders can " \
                   "only rely on backports, config mitigations or network isolation — expect this class of target " \
                   "to be prioritised by attackers.",
                   version: verdict.version, branch: verdict.branch)
      end

      if environment.waf
        notes << t("data.red_team.exposed.waf",
                   "WAF fingerprint: %{waf}. That changes exploit reliability, not exposure — the " \
                   "interpreter is still unpatched behind it. Finding the origin is usually the cheaper path.",
                   waf: environment.waf)
      end

      if environment.cdn?
        notes << t("data.red_team.exposed.cdn",
                   "CDN in front (%{cdn}): WAF rules protect the front door only. If the origin IP " \
                   "leaks (old DNS records, mail headers, certs on Censys/Shodan), direct-to-origin traffic skips " \
                   "every control.",
                   cdn: environment.cdn)
      end

      notes << t("data.red_team.exposed.opsec",
                 "Opsec: the memory-disclosure variant leaks data without crashing the worker, so availability " \
                 "monitoring alone will not reveal the probing phase. Exploitation attempts may look like ordinary " \
                 "large form submissions.")
      notes
    end

    def self.unverified_notes(verdict, environment)
      notes = []
      if verdict.access&.blocked?
        notes << t("data.red_team.unverified.blocked",
                   "A 403 is an observation about the edge, not about the interpreter. Attackers will try other " \
                   "egress, other hostnames, or the origin before concluding anything.")
      elsif verdict.access&.state == :auth_wall
        notes << t("data.red_team.unverified.auth_wall",
                   "The login wall does not close this bug class: the parser runs before authentication. It does " \
                   "mean the reachable surface is narrower until credentials (or an authorized authenticated test) " \
                   "exist.")
      elsif verdict.access&.state == :soft_404
        notes << t("data.red_team.unverified.soft_404",
                   "Catch-all routing makes path fuzzing useless here; attackers will pivot to header/cookie " \
                   "evidence and host-side fingerprinting instead.")
      else
        notes << t("data.red_team.unverified.no_response",
                   "No usable application response was obtained. Treat the host as unassessed and verify from " \
                   "another vantage point before drawing a conclusion.")
      end

      notes << t("data.red_team.unverified.canary",
                 "The random canary path this scanner requests is a detectable signature; a defender watching " \
                 "for it can distinguish reconnaissance from normal traffic.")
      if environment.cdn?
        notes << t("data.red_team.unverified.origin",
                   "Origin discovery is the next step if a CDN is present: certificate transparency, historical DNS, " \
                   "and internet-wide scan data often expose the real host.")
      end
      if environment.waf && environment.waf != "unidentified edge control"
        notes << t("data.red_team.unverified.waf",
                   "If a WAF is present (%{waf}), do not assume it covers this CVE — presence is not " \
                   "rule coverage.", waf: environment.waf)
      end
      notes
    end

    def self.patched_notes
      [
        t("data.red_team.patched.no_chain",
          "No kill chain for this bug class: the interpreter meets the fix level. Pivot to application-layer " \
          "bugs, framework/plugin versions and misconfiguration."),
        t("data.red_team.patched.siblings",
          "A patched flagship host says nothing about sibling subdomains, staging boxes or forgotten vhosts; " \
          "that is where the same branch usually survives.")
      ]
    end

    def self.no_php_notes
      [
        t("data.red_team.no_php.routes",
          "No PHP was observed on the tested routes. Check other vhosts, ports and applications before treating " \
          "the estate as PHP-free."),
        t("data.red_team.no_php.static",
          "A static front end can hide a PHP admin or API behind a different Host header or path.")
      ]
    end

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end
    private_class_method :t
  end
end
