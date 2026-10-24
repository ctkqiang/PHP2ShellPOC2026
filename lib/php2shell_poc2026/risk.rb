# frozen_string_literal: true

require_relative "i18n"

module PHP2ShellPOC2026
  # Exposure severity and exploit friction are different questions, so they
  # get different numbers. A vulnerable interpreter behind a WAF is still a
  # 9.8 exposure; the WAF changes how likely exploitation is, not how bad it
  # would be if it landed. The old model folded both into one score and
  # subtracted points for a CDN, which made an unpatched origin look less
  # severe than it was.
  module Risk
    BASE = {
      vulnerable: 9.8,
      eol: 10.0,
      patched: 0.0,
      no_php: 0.0
    }.freeze

    def self.assess(verdict, environment)
      score = BASE[verdict.status]
      {
        score: score,
        grade: score.nil? ? "UNKNOWN" : grade(score),
        scale: I18n.t("data.risk.scale", default: "exposure severity (CVSS-shaped, not a CVSS vector)"),
        friction: friction(verdict, environment)
      }
    end

    def self.friction(verdict, environment)
      factors = []

      if environment.waf
        factors << { factor: "waf", weight: 3,
                     note: I18n.t("data.risk.friction.waf",
                                  default: "%{waf} may block crafted requests", waf: environment.waf) }
      end
      if environment.cdn?
        factors << { factor: "cdn", weight: 1,
                     note: I18n.t("data.risk.friction.cdn",
                                  default: "%{cdn} masks the origin; direct-to-origin may bypass edge rules",
                                  cdn: environment.cdn) }
      end
      if environment.sapi.to_s.start_with?("php-fpm")
        factors << { factor: "sapi", weight: 1,
                     note: I18n.t("data.risk.friction.sapi",
                                  default: "FPM requires both exploit requests on the same worker") }
      end
      if verdict.access&.state == :auth_wall
        factors << { factor: "auth", weight: 4,
                     note: I18n.t("data.risk.friction.auth",
                                  default: "authentication wall limits reachable paths") }
      end
      if verdict.access&.state == :rate_limited
        factors << { factor: "rate_limit", weight: 3,
                     note: I18n.t("data.risk.friction.rate_limit",
                                  default: "rate limiting slows or blocks request sequences") }
      end
      if verdict.access&.state == :blocked
        factors << { factor: "edge_block", weight: 5,
                     note: I18n.t("data.risk.friction.edge_block",
                                  default: "edge denied every probe; no application-level evidence") }
      end
      if verdict.access&.state == :soft_404
        factors << { factor: "soft_404", weight: 2,
                     note: I18n.t("data.risk.friction.soft_404",
                                  default: "catch-all routing makes path-based evidence unreliable") }
      end

      total = factors.sum { |f| f[:weight] }
      level = if total >= 5 then "high"
              elsif total >= 3 then "medium"
              elsif total.positive? then "low"
              else "none"
              end

      { score: [total, 10].min, level: level, factors: factors }
    end

    def self.grade(score)
      case score
      when 9.0..10.0 then "CRITICAL"
      when 7.0..8.9  then "HIGH"
      when 4.0..6.9  then "MEDIUM"
      when 0.1..3.9  then "LOW"
      else                "NONE"
      end
    end

    def self.grade_code(grade)
      {
        "CRITICAL" => "CRIT", "HIGH" => "HIGH", "MEDIUM" => "MED",
        "LOW" => "LOW", "NONE" => "NONE", "UNKNOWN" => "UNK"
      }.fetch(grade, "?")
    end
  end
end
