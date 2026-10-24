# frozen_string_literal: true

require_relative "i18n"

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
      :signals, :friction, :answer, :action,
      keyword_init: true
    ) do
      # The question a decision-maker actually asks: "can this host be
      # hacked by PHP2Shell?" The rating is the evidence; the answer is
      # the decision. :unknown is deliberately not nil — "no answer yet"
      # is itself the answer until more evidence arrives.
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
          answer: answer,
          action: action,
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
      answer, action = decision_for(rating, verdict)

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
        friction:      risk[:friction],
        answer:        answer,
        action:        action
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

    # Collapses the evidence rating into the yes/no/unknown a decision-maker
    # can act on, plus the one sentence of advice that follows from it.
    # LIKELY is answered YES: in a patch-or-die decision the burden is on
    # disproving exposure, and "likely" does not do that.
    def self.decision_for(rating, verdict = nil)
      case rating
      when :exposed, :likely
        [:yes, t("data.hackability.action.yes",
                 "upgrade PHP now; isolate the host until it is fixed")]
      when :not_exposed
        action = if verdict&.no_php?
                   t("data.hackability.action.no_php",
                     "no PHP was seen on the pages tested; check sibling hosts or other ports before " \
                     "treating the estate as clear")
                 else
                   t("data.hackability.action.no",
                     "no action needed on the pages tested; check again after the next PHP update")
                 end
        [:no, action]
      else
        [:unknown, t("data.hackability.action.unknown",
                     "run a deeper scan or check the PHP version on the host before deciding")]
      end
    end

    def self.build_signals(verdict, environment)
      signals = []

      case verdict.status
      when :vulnerable
        signals << positive(4, :exposure,
                            t("data.hackability.signal.vulnerable",
                              "interpreter %{version} sits below the %{branch} fix level (%{floor})",
                              version: verdict.version, branch: verdict.branch, floor: verdict.fix_floor))
      when :eol
        signals << positive(5, :exposure,
                            t("data.hackability.signal.eol",
                              "branch %{branch} is end-of-life — no upstream fix exists", branch: verdict.branch))
      when :patched
        signals << negative(6, :exposure,
                            t("data.hackability.signal.patched",
                              "interpreter %{version} meets the fix level (%{floor})",
                              version: verdict.version, floor: verdict.fix_floor))
      when :no_php
        signals << negative(4, :exposure,
                            t("data.hackability.signal.no_php",
                              "no PHP markers on the reachable paths; control path behaved normally"))
      when :unknown
        signals << neutral(0, :evidence,
                           t("data.hackability.signal.unknown",
                             "PHP is present but the version was not exposed"))
      when :inconclusive
        signals << neutral(0, :evidence,
                           t("data.hackability.signal.inconclusive",
                             "no usable application evidence — %{reason}", reason: verdict.reason_code))
      end

      surface = verdict.attack_surface

      if verdict.exposed? || verdict.status == :unknown
        if surface[:php_detected]
          signals << positive(1, :surface, t("data.hackability.signal.php", "PHP behaviour observed"))
        end
        if surface[:upload_progress]
          signals << positive(2, :surface,
                              t("data.hackability.signal.upload",
                                "PHPSESSID issued — upload-progress path reachable"))
        end
        if surface[:phpinfo_exposed]
          signals << positive(1, :surface, t("data.hackability.signal.phpinfo", "phpinfo() publicly readable"))
        end
        if surface[:php_errors]
          signals << positive(1, :surface,
                              t("data.hackability.signal.errors", "verbose PHP error text in responses"))
        end
        if surface[:php_paths_live]
          signals << positive(1, :surface,
                              t("data.hackability.signal.live_php",
                                "live .php route confirmed against a 404 control"))
        end
        if surface[:framework]
          signals << positive(1, :surface,
                              t("data.hackability.signal.framework", "PHP framework detected: %{framework}",
                                framework: surface[:framework]))
        end
      end

      if verdict.exposed?
        signals << positive(2, :exposure,
                            t("data.hackability.signal.pre_auth",
                              "fires before authentication — the parser runs before application code"))
        if environment.waf
          signals << neutral(0, :friction,
                             t("data.hackability.signal.waf", "WAF (%{waf}) in front", waf: environment.waf))
        end
        if environment.cdn?
          signals << neutral(0, :friction,
                             t("data.hackability.signal.cdn", "CDN (%{cdn}) masks the origin", cdn: environment.cdn))
        end
        if environment.sapi.to_s.start_with?("php-fpm")
          signals << neutral(0, :friction,
                             t("data.hackability.signal.fpm",
                               "php-fpm posture — same-worker request pairing required"))
        end
      end

      if verdict.access&.blocked?
        signals << neutral(0, :evidence,
                           t("data.hackability.signal.blocked",
                             "edge denied every probe (HTTP %{statuses})",
                             statuses: verdict.access&.details&.dig(:statuses)&.join("/") || "4xx"))
      end
      if verdict.access&.state == :soft_404
        signals << neutral(0, :evidence,
                           t("data.hackability.signal.soft_404",
                             "catch-all 200 responses — path evidence unreliable"))
      end
      if verdict.reason_code == :branch_only
        signals << neutral(0, :evidence,
                           t("data.hackability.signal.branch_only",
                             "version reported at branch level only — patch level unknown"))
      end

      signals
    end

    def self.prerequisites(verdict, environment)
      if verdict.exposed?
        prereqs = [t("data.hackability.prereq.reachability",
                     "TCP reachability to the web port — no credentials, session or user interaction")]
        prereqs << if verdict.attack_surface[:upload_progress]
                     t("data.hackability.prereq.upload",
                       "multipart POST accepted with PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID (CVE-2026-109619 arm)")
                   else
                     t("data.hackability.prereq.oom",
                       "upload-progress acceptance unconfirmed — the CVE-2026-109618 (OOM) arm needs no special " \
                       "request fields")
                   end
        if environment.sapi.to_s.start_with?("php-fpm")
          prereqs << t("data.hackability.prereq.fpm",
                       "both crafted requests must land on the same FPM worker")
        end
        prereqs << t("data.hackability.prereq.route",
                     "any live .php route — no specific path, permission or session required")
        prereqs
      elsif verdict.patched?
        [t("data.hackability.prereq.patched", "none — this bug class is closed at the interpreter fix level")]
      elsif verdict.no_php?
        [t("data.hackability.prereq.no_php",
           "a PHP endpoint outside the probed paths — this finding covers the routes that were actually tested")]
      else
        [t("data.hackability.prereq.unverified",
           "a usable application response or a host-side version read before exposure can be assessed")]
      end
    end

    def self.reliability(verdict, environment)
      if verdict.patched?
        return t("data.hackability.reliability.patched",
                 "closed — interpreter meets the fix level; nothing to assess")
      end
      if verdict.no_php?
        return t("data.hackability.reliability.no_php",
                 "not applicable — no PHP surface observed on the probed paths")
      end
      if verdict.unverified?
        return t("data.hackability.reliability.unverified",
                 "undetermined — no usable application response; measure from an approved vantage point")
      end

      sapi = environment.sapi.to_s

      if sapi.start_with?("mod_php")
        t("data.hackability.reliability.mod_php",
          "high — mod_php gives one process per request with no recycle between victims; first-shot success is realistic")
      elsif sapi.start_with?("php-fpm")
        t("data.hackability.reliability.fpm",
          "moderate — FPM forces request pairing onto a single worker; expect retries and partial failures")
      else
        t("data.hackability.reliability.unknown",
          "undetermined — SAPI not fingerprintable from outside; measure worker behaviour before trusting either model")
      end
    end

    def self.impact(verdict)
      if verdict.exposed?
        t("data.hackability.impact.exposed",
          "code execution as the web worker UID (T1059.004) with webshell persistence (T1505.003); " \
          "or silent memory disclosure of env vars, keys and session material (T1005) with no crash")
      elsif verdict.patched?
        t("data.hackability.impact.patched",
          "parser-level exploitation closed at the fix level — residual risk is application bugs and misconfiguration")
      elsif verdict.no_php?
        t("data.hackability.impact.no_php",
          "not applicable to the probed routes — this bug class requires a PHP interpreter")
      else
        t("data.hackability.impact.unknown",
          "undetermined — impact cannot be assigned until the interpreter version is confirmed")
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

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end
    private_class_method :t
  end
end
