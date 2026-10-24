# frozen_string_literal: true

module PHP2ShellPOC2026
  # Evidence weighing for the question people ask at the bottom of a report:
  # is this host exploitable by this bug class, and how much of that answer
  # is backed by observed signals?
  #
  # The 3.0 model separates *exposure* (is the interpreter vulnerable?) from
  # *friction* (what would an attacker have to beat?). A WAF is not evidence
  # that PHP is patched, and a 403 is not evidence that PHP is absent. When
  # there is no positive or negative evidence at all, the ratio is nil and
  # the rating is INCONCLUSIVE — not "0.00, therefore safe".
  module Hackability
    Signal = Struct.new(:direction, :weight, :kind, :label, keyword_init: true) do
      def to_h
        { direction: direction, weight: weight, kind: kind, label: label }
      end
    end

    Result = Struct.new(
      :rating, :label, :ratio, :positive, :negative, :neutral,
      :confidence, :coverage, :prerequisites, :reliability, :impact,
      :signals, :friction,
      keyword_init: true
    ) do
      def hackable?
        return true if rating == :exposed || rating == :likely
        return false if rating == :not_exposed

        nil
      end

      def to_h
        {
          rating: rating,
          label: label,
          ratio: ratio,
          positive: positive,
          negative: negative,
          neutral: neutral,
          hackable: hackable?,
          confidence: confidence,
          coverage: coverage,
          prerequisites: prerequisites,
          reliability: reliability,
          impact: impact,
          friction: friction,
          signals: signals.map(&:to_h)
        }
      end
    end

    RATINGS = {
      exposed: "EXPOSED",
      likely: "LIKELY EXPOSED",
      inconclusive: "INCONCLUSIVE",
      not_exposed: "NOT EXPOSED"
    }.freeze

    def self.assess(verdict, environment, risk, coverage: {})
      signals  = build_signals(verdict, environment)
      positive = signals.select { |s| s.direction == :positive }.sum(&:weight)
      negative = signals.select { |s| s.direction == :negative }.sum(&:weight)
      neutral  = signals.select { |s| s.direction == :neutral }.sum(&:weight)
      total    = positive + negative
      ratio    = total.zero? ? nil : (positive.to_f / total).round(2)
      rating   = rate(ratio, verdict)

      Result.new(
        rating:        rating,
        label:         RATINGS.fetch(rating),
        ratio:         ratio,
        positive:      positive,
        negative:      negative,
        neutral:       neutral,
        confidence:    verdict.confidence,
        coverage:      coverage,
        prerequisites: prerequisites(verdict, environment),
        reliability:   reliability(verdict, environment),
        impact:        impact(verdict),
        signals:       signals,
        friction:      risk[:friction]
      )
    end

    def self.rate(ratio, verdict)
      return :not_exposed if verdict.patched? || verdict.no_php?
      return :inconclusive if verdict.unverified?
      return :inconclusive unless ratio

      if ratio >= 0.6
        :exposed
      else
        :likely
      end
    end

    def self.build_signals(verdict, environment)
      signals = []

      case verdict.status
      when :vulnerable
        signals << positive(4, :exposure, "interpreter #{verdict.version} sits below the #{verdict.branch} fix level (#{verdict.fix_floor})")
      when :eol
        signals << positive(5, :exposure, "branch #{verdict.branch} is end-of-life — no upstream fix exists")
      when :patched
        signals << negative(6, :exposure, "interpreter #{verdict.version} meets the fix level (#{verdict.fix_floor})")
      when :no_php
        signals << negative(4, :exposure, "no PHP markers on the reachable paths; control path behaved normally")
      when :unknown
        signals << neutral(0, :evidence, "PHP is present but the version was not exposed")
      when :inconclusive
        signals << neutral(0, :evidence, "no usable application evidence — #{verdict.reason_code}")
      end

      surface = verdict.attack_surface

      if verdict.exposed? || verdict.status == :unknown
        signals << positive(1, :surface, "PHP behaviour observed") if surface[:php_detected]
        signals << positive(2, :surface, "PHPSESSID issued — upload-progress path reachable") if surface[:upload_progress]
        signals << positive(1, :surface, "phpinfo() publicly readable") if surface[:phpinfo_exposed]
        signals << positive(1, :surface, "verbose PHP error text in responses") if surface[:php_errors]
        signals << positive(1, :surface, "live .php route confirmed against a 404 control") if surface[:php_paths_live]
        signals << positive(1, :surface, "PHP framework detected: #{surface[:framework]}") if surface[:framework]
      end

      if verdict.exposed?
        signals << positive(2, :exposure, "fires before authentication — the parser runs before application code")
        signals << neutral(0, :friction, "WAF (#{environment.waf}) in front") if environment.waf
        signals << neutral(0, :friction, "CDN (#{environment.cdn}) masks the origin") if environment.cdn?
        signals << neutral(0, :friction, "php-fpm posture — same-worker request pairing required") if environment.sapi.to_s.start_with?("php-fpm")
      end

      signals << neutral(0, :evidence, "edge denied every probe (HTTP #{verdict.access&.details&.dig(:statuses)&.join('/') || '4xx'})") if verdict.access&.blocked?
      signals << neutral(0, :evidence, "catch-all 200 responses — path evidence unreliable") if verdict.access&.state == :soft_404
      signals << neutral(0, :evidence, "version reported at branch level only — patch level unknown") if verdict.reason_code == :branch_only

      signals
    end

    def self.prerequisites(verdict, environment)
      if verdict.exposed?
        prereqs = ["TCP reachability to the web port — no credentials, session or user interaction"]
        prereqs << if verdict.attack_surface[:upload_progress]
                     "multipart POST accepted with PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID (CVE-2026-109619 arm)"
                   else
                     "upload-progress acceptance unconfirmed — the CVE-2026-109618 (OOM) arm needs no special request fields"
                   end
        prereqs << "both crafted requests must land on the same FPM worker" if environment.sapi.to_s.start_with?("php-fpm")
        prereqs << "any live .php route — no specific path, permission or session required"
        prereqs
      elsif verdict.patched?
        ["none — this bug class is closed at the interpreter fix level"]
      elsif verdict.no_php?
        ["a PHP endpoint outside the probed paths — this finding covers the routes that were actually tested"]
      else
        ["a usable application response or a host-side version read before exposure can be assessed"]
      end
    end

    def self.reliability(verdict, environment)
      return "closed — interpreter meets the fix level; nothing to assess" if verdict.patched?
      return "not applicable — no PHP surface observed on the probed paths" if verdict.no_php?
      return "undetermined — no usable application response; measure from an approved vantage point" if verdict.unverified?

      sapi = environment.sapi.to_s

      if sapi.start_with?("mod_php")
        "high — mod_php gives one process per request with no recycle between victims; first-shot success is realistic"
      elsif sapi.start_with?("php-fpm")
        "moderate — FPM forces request pairing onto a single worker; expect retries and partial failures"
      else
        "undetermined — SAPI not fingerprintable from outside; measure worker behaviour before trusting either model"
      end
    end

    def self.impact(verdict)
      if verdict.exposed?
        "code execution as the web worker UID (T1059.004) with webshell persistence (T1505.003); " \
          "or silent memory disclosure of env vars, keys and session material (T1005) with no crash"
      elsif verdict.patched?
        "parser-level exploitation closed at the fix level — residual risk is application bugs and misconfiguration"
      elsif verdict.no_php?
        "not applicable to the probed routes — this bug class requires a PHP interpreter"
      else
        "undetermined — impact cannot be assigned until the interpreter version is confirmed"
      end
    end

    def self.positive(weight, kind, label)
      Signal.new(direction: :positive, weight: weight, kind: kind, label: label)
    end

    def self.negative(weight, kind, label)
      Signal.new(direction: :negative, weight: weight, kind: kind, label: label)
    end

    def self.neutral(weight, kind, label)
      Signal.new(direction: :neutral, weight: weight, kind: kind, label: label)
    end
  end
end
