# frozen_string_literal: true

module PHP2ShellPOC2026
  # The answer to "is this host exposed?", together with the reasoning that
  # got us there. It is a class rather than a bare hash because three separate
  # consumers act on it — the CLI turns it into an exit code, the risk model
  # turns it into a score, the ATT&CK mapper uses `exposed?` to decide whether
  # there is a chain worth reporting at all — and all three should be working
  # from one shared definition of what a status means.
  class Verdict
    # First release in each supported branch that ships the PHP2Shell fix.
    # Branches absent from this table (5.x, 7.x, 8.1) never received one:
    # they are end-of-life, and between them and the bug stand only distro
    # backports that nobody has confirmed are actually applied.
    FIXED_RELEASES = {
      "8.2" => Gem::Version.new("8.2.35"),
      "8.3" => Gem::Version.new("8.3.36"),
      "8.4" => Gem::Version.new("8.4.27"),
      "8.5" => Gem::Version.new("8.5.12")
    }.freeze

    NO_FINGERPRINT =
      "no PHP version fingerprint exposed — try --deep, or read the version off the host directly"

    attr_reader :status, :version, :version_source, :reason, :attack_surface

    def initialize(status:, reason:, version: nil, version_source: nil, attack_surface: {})
      @status         = status
      @version        = version
      @version_source = version_source
      @reason         = reason
      @attack_surface = attack_surface
    end

    # Branch order is deliberate. No fingerprint at all short-circuits to
    # :unknown; a branch with no entry in FIXED_RELEASES is EOL before we ask
    # anything else, because telling someone on 7.4 to "upgrade to 8.2.35" is
    # technically true and practically useless. Only branches that do have a
    # published fix get compared against their floor.
    def self.assess(version, attack_surface = {}, version_source = nil)
      unless version
        return new(status: :unknown, reason: NO_FINGERPRINT,
                   attack_surface: attack_surface)
      end

      branch = version.segments[0, 2].join(".")
      floor  = FIXED_RELEASES[branch]

      if floor.nil?
        new(status: :eol, version: version, version_source: version_source,
            attack_surface: attack_surface,
            reason: "PHP #{version} (branch #{branch}) is end-of-life — no upstream fix exists; " \
                    "only distro backports (7.4/8.0/8.1) or an upgrade will clear this")
      elsif version >= floor
        new(status: :patched, version: version, version_source: version_source,
            attack_surface: attack_surface,
            reason: "PHP #{version} is at or above the #{branch} fix level (#{floor})")
      else
        new(status: :vulnerable, version: version, version_source: version_source,
            attack_surface: attack_surface,
            reason: "PHP #{version} is below the #{branch} fix level (#{floor}) — update now")
      end
    end

    # Every downstream decision hangs off this predicate. EOL counts as
    # exposed on purpose: "no fix exists" is a worse answer than "below the
    # fix level", not a better one.
    def exposed?
      status == :vulnerable || status == :eol
    end

    def to_h
      {
        status:         status,
        version:        version && version.to_s,
        version_source: version_source,
        reason:         reason,
        attack_surface: attack_surface
      }
    end
  end
end
