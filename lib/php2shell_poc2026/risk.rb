# frozen_string_literal: true

module PHP2ShellPOC2026
  # Exposure-weighted scoring. The base number comes from the verdict —
  # this is a CVSS-shaped scale, not a literal CVSS vector — and then moves
  # for what the deployment makes of the bug: mod_php earns points because
  # exploitation is one-shot reliable, FPM loses them because both requests
  # must land on the same worker, and a CDN in front buys a point back only
  # because origin bypass is a separate and very common failure mode.
  #
  # Scores are capped at 10.0 before grading; nothing here is meant to be
  # compared against a vendor's official CVSS for this CVE.
  module Risk
    BASE = { vulnerable: 9.8, eol: 10.0, patched: 0.0, unknown: 4.0 }.freeze

    def self.assess(verdict, environment)
      base = BASE.fetch(verdict.status, BASE[:unknown])
      score = apply_sapi(base, verdict, environment)
      score -= 1.0 if environment.cdn? && verdict.status != :patched
      score = score.round(1).clamp(0.0, 10.0)

      { score: score, grade: grade(score), scale: "CVSS-like, exposure-weighted" }
    end

    # Kept as its own step because SAPI reliability is the one variable that
    # changes exploit odds rather than exposure — worth seeing separately in
    # the score's construction, even though the final number hides it.
    def self.apply_sapi(base, verdict, environment)
      sapi = environment.sapi.to_s

      if sapi.start_with?("mod_php") && verdict.status != :patched
        [base + 0.2, 10.0].min
      elsif sapi.start_with?("php-fpm") && verdict.status == :vulnerable
        base - 1.0
      else
        base
      end
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
  end
end
