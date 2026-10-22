# frozen_string_literal: true

module PHP2ShellPOC2026
  # Evidence weighing for the question people actually ask at the bottom of
  # a report: is this host hackable *by this bug class*, and how much of that
  # answer is backed by signals we observed rather than assumed?
  #
  # Every observed fact contributes a signed weight. The positivity ratio is
  # positive / (positive + negative) — 1.0 means every signal points at
  # exploitability, 0.0 means none do — and the rating falls out of that
  # ratio. Two clamps keep the number honest: a host with no PHP behaviour
  # observed can never rate above NOT HACKABLE, and an unconfirmed
  # fingerprint can never rate above LIKELY, however many supporting signals
  # pile up, because "we could not read the version" is not evidence of
  # exposure.
  #
  # Risk and hackability answer different questions on purpose. Risk scores
  # severity of the exposure (an EOL interpreter behind a CDN is still a 10);
  # hackability scores how confidently the evidence supports exploiting *this
  # host* right now. A CRITICAL risk can legitimately print LIKELY HACKABLE
  # when the edge is hiding the origin.
  module Hackability
    Signal = Struct.new(:direction, :weight, :label, keyword_init: true)

    Result = Struct.new(
      :rating, :label, :ratio, :positive, :negative,
      :prerequisites, :reliability, :impact, :signals,
      keyword_init: true
    ) do
      def hackable?
        rating == :hackable || rating == :likely
      end

      def to_h
        {
          rating:         rating,
          label:          label,
          ratio:          ratio,
          positive:       positive,
          negative:       negative,
          hackable:       hackable?,
          prerequisites:  prerequisites,
          reliability:    reliability,
          impact:         impact,
          signals:        signals.map(&:to_h)
        }
      end
    end

    RATINGS = {
      hackable:     "HACKABLE",
      likely:       "LIKELY HACKABLE",
      uncertain:    "INCONCLUSIVE",
      not_hackable: "NOT HACKABLE"
    }.freeze

    def self.assess(verdict, environment)
      surface  = verdict.attack_surface
      signals  = build_signals(verdict, environment, surface)
      positive = signals.select { |s| s.direction == :positive }.sum(&:weight)
      negative = signals.select { |s| s.direction == :negative }.sum(&:weight)
      total    = positive + negative
      ratio    = total.zero? ? 0.0 : (positive.to_f / total).round(2)
      rating   = rate(ratio, verdict, surface)

      Result.new(
        rating:        rating,
        label:         RATINGS.fetch(rating),
        ratio:         ratio,
        positive:      positive,
        negative:      negative,
        prerequisites: prerequisites(verdict, environment, surface),
        reliability:   reliability(verdict, environment),
        impact:        impact(verdict),
        signals:       signals
      )
    end

    def self.rate(ratio, verdict, surface)
      rating =
        if !surface[:php_detected]           then :not_hackable
        elsif ratio >= 0.75                  then :hackable
        elsif ratio >= 0.50                  then :likely
        elsif ratio >= 0.25                  then :uncertain
        else                                      :not_hackable
        end

      # An unreadable version caps the ceiling, never raises it: unknown
      # means exactly that, and the report should not sound confident on
      # the back of an absence.
      rating == :hackable && verdict.status == :unknown ? :likely : rating
    end

    def self.build_signals(verdict, environment, surface)
      signals = []

      case verdict.status
      when :vulnerable
        signals << positive_signal(4, "interpreter #{verdict.version} sits below its branch fix level")
      when :eol
        signals << positive_signal(5, "branch #{branch_of(verdict)} is end-of-life — no upstream fix exists")
      when :unknown
        signals << negative_signal(3, "no version fingerprint — exposure unconfirmed")
      when :patched
        signals << negative_signal(6, "meets the fix level (#{verdict.version}) — parser-level exploit closed")
      end

      unless surface[:php_detected]
        signals << negative_signal(3, "no PHP behaviour observed on probed paths")
        return signals
      end

      # Environment and surface signals only speak to hackability when the
      # interpreter is actually in play — a patched host does not become
      # more exploitable because no WAF was seen.
      if verdict.status != :patched
        signals << positive_signal(2, "fires pre-authentication — parser runs before any application code")
        signals << positive_signal(2, "PHPSESSID issued — CVE-2026-109619 upload-progress path reachable") if surface[:upload_progress]
        signals << positive_signal(1, "phpinfo() publicly readable — interpreter confirmed executing") if surface[:phpinfo_exposed]
        signals << positive_signal(1, "verbose PHP error text in responses") if surface[:php_errors]
        signals << positive_signal(1, "live .php entry points return 2xx/3xx")
        signals << positive_signal(2, "no WAF fingerprint observed — no edge rule in the way") unless environment.waf
        signals << positive_signal(1, "no CDN — requests reach the origin directly") unless environment.cdn?

        if environment.sapi.start_with?("mod_php")
          signals << positive_signal(2, "mod_php posture — one process per request, exploitation is one-shot")
        end
      end

      signals << negative_signal(1, "behind #{environment.cdn} — origin may run different PHP; the edge masks the truth") if environment.cdn?
      signals << negative_signal(2, "WAF (#{environment.waf}) in front — crafted bodies may be blocked") if environment.waf

      if environment.sapi.start_with?("php-fpm") && verdict.exposed?
        signals << negative_signal(1, "php-fpm posture — both exploit requests must land on the same worker")
      end

      signals
    end

    def self.prerequisites(verdict, environment, surface)
      prereqs = ["TCP reachability to the web port — no credentials, session or user interaction"]

      if verdict.exposed?
        prereqs << if surface[:upload_progress]
                     "multipart POST accepted with PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID (CVE-2026-109619 arm)"
                   else
                     "upload-progress acceptance unconfirmed — the CVE-2026-109618 (OOM) arm needs no special request fields"
                   end
        prereqs << "both crafted requests must land on the same FPM worker" if environment.sapi.start_with?("php-fpm")
        prereqs << "any live .php route — no specific path, permission or session required"
      elsif verdict.status == :unknown
        prereqs << "confirm the interpreter version first (--deep, or a host-side read) before committing effort"
      else
        prereqs << "none applicable — this bug class is closed at the interpreter fix level"
      end

      prereqs
    end

    def self.reliability(verdict, environment)
      return "closed — interpreter meets the fix level; nothing to assess" if verdict.status == :patched

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
      elsif verdict.status == :patched
        "parser-level exploitation closed at the fix level — residual risk is application bugs and misconfiguration"
      else
        "undetermined — impact cannot be assigned until the interpreter version is confirmed"
      end
    end

    def self.branch_of(verdict)
      verdict.version && verdict.version.segments[0, 2].join(".")
    end

    def self.positive_signal(weight, label)
      Signal.new(direction: :positive, weight: weight, label: label)
    end

    def self.negative_signal(weight, label)
      Signal.new(direction: :negative, weight: weight, label: label)
    end
  end
end
