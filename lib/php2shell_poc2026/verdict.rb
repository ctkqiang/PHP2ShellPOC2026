# frozen_string_literal: true

require "rubygems"
require_relative "sanitize"

module PHP2ShellPOC2026
  # The answer to "is this host exposed?", together with the reasoning that
  # got us there. The important change in 3.0 is that a failure to observe
  # is no longer mistaken for a clean bill of health: blocked, unreachable
  # and unversioned hosts get their own statuses instead of collapsing into
  # "not hackable".
  class Verdict
    # First release in each supported branch that ships the PHP2Shell fix.
    # Branches absent from this table (5.x, 7.x, 8.0, 8.1) are end-of-life
    # and never received an upstream fix. A branch newer than the table is
    # reported as unverified rather than guessed.
    FIXED_RELEASES = {
      "8.2" => Gem::Version.new("8.2.35"),
      "8.3" => Gem::Version.new("8.3.36"),
      "8.4" => Gem::Version.new("8.4.27"),
      "8.5" => Gem::Version.new("8.5.12")
    }.freeze

    KNOWN_EOL_BRANCHES = %w[5.0 5.1 5.2 5.3 5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1].freeze

    STATUSES = {
      vulnerable: "vulnerable",
      eol: "end-of-life",
      patched: "patched",
      unknown: "unverified (PHP present, version unknown)",
      no_php: "no PHP surface observed",
      inconclusive: "inconclusive"
    }.freeze

    attr_reader :status, :reason_code, :reason, :version, :version_source,
                :version_precision, :confidence, :attack_surface, :access,
                :branch, :fix_floor

    def initialize(status:, reason_code:, reason:, version: nil, version_source: nil,
                   version_precision: nil, confidence: "low", attack_surface: {},
                   access: nil, branch: nil, fix_floor: nil)
      @status           = status
      @reason_code      = reason_code
      @reason           = reason
      @version          = version
      @version_source   = version_source
      @version_precision = version_precision
      @confidence       = confidence
      @attack_surface   = attack_surface
      @access           = access
      @branch           = branch
      @fix_floor        = fix_floor
    end

    def self.assess(version: nil, version_source: nil, precision: nil, surface: {}, access: nil)
      version = parse_version(version)
      precision ||= infer_precision(version)
      access_state = access && access.state

      # An edge denial is not evidence about the interpreter. If a version
      # leaked anyway (some WAF error pages carry X-Powered-By), report it
      # but cap confidence at low and say so.
      if %i[blocked unreachable rate_limited server_error].include?(access_state)
        if version
          return versioned(version, version_source, precision, surface, access, :low,
                           " — observed on an error response; #{access.reason}")
        end
        return new(status: :inconclusive, reason_code: access_state,
                   reason: "#{access.reason} — exposure is unverified, not absent",
                   confidence: "low", attack_surface: surface, access: access)
      end

      if access_state == :restricted
        if version
          return versioned(version, version_source, precision, surface, access, :low,
                           " — root path restricted; #{access.reason}")
        end
        return new(status: :inconclusive, reason_code: :restricted,
                   reason: "#{access.reason} — the interpreter could not be assessed",
                   confidence: "low", attack_surface: surface, access: access)
      end

      if access_state == :auth_wall && version.nil?
        return new(status: :inconclusive, reason_code: :auth_wall,
                   reason: "#{access.reason} — read the version host-side or assess the authenticated surface only with authorization",
                   confidence: "low", attack_surface: surface, access: access)
      end

      if access_state == :soft_404 && version.nil?
        return new(status: :inconclusive, reason_code: :soft_404,
                   reason: "#{access.reason} — no version header was exposed, so exposure is unverified",
                   confidence: "low", attack_surface: surface, access: access)
      end

      unless version
        if surface[:php_detected]
          return new(status: :unknown, reason_code: :no_version,
                     reason: "PHP is present but no version was exposed — exposure is unconfirmed; " \
                             "try --profile deep or read the version host-side",
                     confidence: access_state == :open ? "medium" : "low",
                     attack_surface: surface, access: access)
        end

        return new(status: :no_php, reason_code: :no_php,
                   reason: "no PHP markers were observed on the reachable paths and the control path behaved normally — " \
                           "no PHP surface found on this route (this is not proof that other vhosts are PHP-free)",
                   confidence: access_state == :open ? "medium" : "low",
                   attack_surface: surface, access: access)
      end

      versioned(version, version_source, precision, surface, access,
                confidence_for(version, precision, version_source, access, surface), nil)
    end

    def self.versioned(version, source, precision, surface, access, confidence, caveat)
      branch = version.segments[0, 2].join(".")
      floor  = FIXED_RELEASES[branch]
      suffix = caveat.to_s

      if precision == :minor
        return new(status: :unknown, reason_code: :branch_only,
                   version: version, version_source: source, version_precision: precision,
                   confidence: "low", attack_surface: surface, access: access,
                   branch: branch, fix_floor: floor,
                   reason: "only a branch-level version (#{version}) was exposed; the patch level is unknown — " \
                           "compare against #{floor || 'the branch fix level'} host-side#{suffix}")
      end

      if floor
        if version >= floor
          new(status: :patched, reason_code: :patched, version: version,
              version_source: source, version_precision: precision, confidence: confidence,
              attack_surface: surface, access: access, branch: branch, fix_floor: floor,
              reason: "PHP #{version} is at or above the #{branch} fix level (#{floor})#{suffix}")
        else
          new(status: :vulnerable, reason_code: :vulnerable, version: version,
              version_source: source, version_precision: precision, confidence: confidence,
              attack_surface: surface, access: access, branch: branch, fix_floor: floor,
              reason: "PHP #{version} is below the #{branch} fix level (#{floor}) — update now#{suffix}")
        end
      elsif KNOWN_EOL_BRANCHES.include?(branch)
        new(status: :eol, reason_code: :eol, version: version, version_source: source,
            version_precision: precision, confidence: confidence, attack_surface: surface,
            access: access, branch: branch, fix_floor: nil,
            reason: "PHP #{version} (branch #{branch}) is end-of-life — no upstream fix exists; " \
                    "only distro backports or an upgrade will clear this#{suffix}")
      elsif Gem::Version.new(branch) > Gem::Version.new(FIXED_RELEASES.keys.max)
        new(status: :unknown, reason_code: :newer_than_table, version: version,
            version_source: source, version_precision: precision, confidence: "low",
            attack_surface: surface, access: access, branch: branch, fix_floor: nil,
            reason: "PHP #{version} is newer than this tool's fix table (#{FIXED_RELEASES.keys.max}.x) — " \
                    "verify against the current PHP release notes#{suffix}")
      else
        new(status: :eol, reason_code: :eol, version: version, version_source: source,
            version_precision: precision, confidence: confidence, attack_surface: surface,
            access: access, branch: branch, fix_floor: nil,
            reason: "PHP #{version} (branch #{branch}) is outside the supported fix table — treat as end-of-life " \
                    "until a vendor advisory says otherwise#{suffix}")
      end
    end

    def self.parse_version(value)
      return nil if value.nil?
      return value if value.is_a?(Gem::Version)

      text = value.to_s[/\d+(?:\.\d+){1,3}/]
      text && Gem::Version.new(text)
    rescue ArgumentError
      nil
    end

    def self.infer_precision(version)
      return nil unless version

      version.segments.length >= 3 ? :patch : :minor
    end

    def self.confidence_for(version, precision, source, access, surface)
      return "low" if precision == :minor
      return "medium" unless access.nil? || access.open?
      return "high" if source.to_s.match?(/header|phpinfo/i)
      return "medium" if surface[:php_detected]

      "low"
    end

    def exposed?
      status == :vulnerable || status == :eol
    end

    def patched?
      status == :patched
    end

    def no_php?
      status == :no_php
    end

    def unverified?
      status == :unknown || status == :inconclusive
    end

    def assessable?
      exposed? || patched? || no_php?
    end

    def label
      case status
      when :vulnerable then "VULNERABLE"
      when :eol then "END-OF-LIFE"
      when :patched then "PATCHED"
      when :unknown then "UNVERIFIED"
      when :no_php then "NO PHP OBSERVED"
      else "INCONCLUSIVE"
      end
    end

    def to_h
      {
        status: status,
        label: label,
        reason_code: reason_code,
        reason: reason,
        version: version && version.to_s,
        version_source: version_source,
        version_precision: version_precision,
        confidence: confidence,
        branch: branch,
        fix_floor: fix_floor && fix_floor.to_s,
        attack_surface: attack_surface,
        access: access && access.to_h,
        exposed: exposed?,
        assessable: assessable?
      }
    end
  end
end
