# frozen_string_literal: true

require_relative "access"
require_relative "attack"
require_relative "detections"
require_relative "environment"
require_relative "hackability"
require_relative "next_actions"
require_relative "probe"
require_relative "remediation"
require_relative "risk"
require_relative "tooling"
require_relative "trace"
require_relative "verdict"
require_relative "version"

module PHP2ShellPOC2026
  # The complete answer for one target. A class rather than a hash so a typo
  # in a key is a NoMethodError at development time instead of a silently
  # empty field in someone's report, and so the CLI, every report format and
  # the tests all read the same shape.
  class ScanResult
    attr_reader :target, :verdict, :environment, :risk, :attack_chain,
                :assessment_path, :detections, :red_team, :tooling,
                :fingerprint, :hackability, :remediation, :next_actions,
                :probes, :trace, :meta, :error

    def initialize(target:, verdict:, environment:, risk:, attack_chain:,
                   assessment_path:, detections:, red_team:, tooling:,
                   fingerprint:, hackability:, remediation:, next_actions:,
                   probes:, trace:, meta:, error: nil)
      @target          = target
      @verdict         = verdict
      @environment     = environment
      @risk            = risk
      @attack_chain    = attack_chain
      @assessment_path = assessment_path
      @detections      = detections
      @red_team        = red_team
      @tooling         = tooling
      @fingerprint     = fingerprint
      @hackability     = hackability
      @remediation     = remediation
      @next_actions    = next_actions
      @probes          = probes
      @trace           = trace
      @meta            = meta
      @error           = error
    end

    def exposed?
      verdict.exposed?
    end

    def patched?
      verdict.patched?
    end

    def no_php?
      verdict.no_php?
    end

    def unverified?
      verdict.unverified?
    end

    def error?
      !error.nil?
    end

    def to_h(include_body: false)
      {
        target: target.to_h,
        verdict: verdict.to_h,
        environment: environment.to_h,
        risk: risk,
        attack: {
          assessment_path: assessment_path.map(&:to_h),
          kill_chain: attack_chain.map(&:to_h)
        },
        detections: detections.map(&:to_h),
        red_team: red_team,
        tooling: tooling.map(&:to_h),
        fingerprint: fingerprint,
        hackability: hackability.to_h,
        remediation: remediation,
        next_actions: next_actions.map(&:to_h),
        probes: probes.map { |probe| probe.to_h(include_body: include_body) },
        trace: trace.lines,
        meta: meta,
        error: error
      }
    end

    # A scan that blew up after target parsing still gets a row in the
    # report. Silently dropping it is how hosts disappear from inventories.
    def self.failed(target, error, options, trace: nil, meta: {})
      probe = Probe.new(uri: target.uri, status: nil, error: "#{error.class}: #{error.message}",
                        error_kind: :internal, purpose: "root")
      probes = [probe]
      access = Access.classify(probes, root: probe)
      surface = {}
      verdict = Verdict.assess(surface: surface, access: access)
      environment = Environment.new(probes, access: access, surface: surface)
      risk = Risk.assess(verdict, environment)
      coverage = { attempted: 1, usable: 0, denied: 0, not_found: 0, errors: 1,
                   rate_limited: 0, server_error: 0, percent: 0.0 }
      hackability = Hackability.assess(verdict, environment, risk, coverage: coverage)
      trace ||= Trace.new(enabled: options.verbose)
      trace.add("xxx #{target.uri}: #{error.class}: #{error.message}")

      new(
        target: target,
        verdict: verdict,
        environment: environment,
        risk: risk,
        attack_chain: [],
        assessment_path: Attack.assessment_path(verdict, environment,
                                                requests: 0, profile: options.profile),
        detections: Detections.for(verdict, environment),
        red_team: RedTeam.notes(verdict, environment),
        tooling: Tooling.catalogue(verdict, environment, options),
        fingerprint: { x_powered_by: nil, server: nil, cookie_names: [], statuses: [],
                       probed_paths: [target.uri.path], titles: [], frameworks: [],
                       framework_versions: [], php_markers: [], version_candidates: [],
                       control: nil, coverage: coverage, tls: nil, dns: nil,
                       discovered_paths: [], requests: 0 },
        hackability: hackability,
        remediation: Remediation.for(verdict, environment),
        next_actions: NextActions.for(verdict, environment, target, options),
        probes: probes,
        trace: trace,
        meta: meta.merge(tool_version: VERSION, duration_ms: 0, requests: 0,
                         profile: options.profile, error: true),
        error: "#{error.class}: #{error.message}"
      )
    end
  end
end
