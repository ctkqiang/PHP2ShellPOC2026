# frozen_string_literal: true

require_relative "sanitize"

module PHP2ShellPOC2026
  # What the edge did with the probe, independent of what PHP is running.
  # This exists because "403 on every path" and "404 on every path" are
  # completely different observations, and the old model collapsed both
  # into "no PHP".
  class Access
    STATES = {
      open: "application responded",
      blocked: "edge denied every probe",
      restricted: "root path denied, control path reachable",
      auth_wall: "authentication wall",
      rate_limited: "rate limited",
      soft_404: "catch-all/soft-404 routing",
      server_error: "origin server error",
      unreachable: "unreachable",
      unknown: "unclassified"
    }.freeze

    LOGIN_PATH = %r{/(?:login|log-in|signin|sign-in|auth|sso|cas|oauth|session|connexion|anmelden|entrar|accedi|inloggen)(?:[/?]|\z)}i
    LOGIN_TEXT = /\b(?:sign in|log in|login|connexion|anmelden|accedi|inloggen|登录|登入)\b/i

    attr_reader :state, :reason, :control, :details

    def initialize(state:, reason:, control: nil, details: {})
      @state   = state
      @reason  = reason
      @control = control
      @details = details
    end

    def self.classify(probes, root: nil)
      main     = probes.reject { |probe| control?(probe) }
      controls = probes.select { |probe| control?(probe) }
      root   ||= main.first
      details  = stats(probes, main, controls)

      return new(state: :unknown, reason: "no probes were completed", details: details) if probes.empty?
      return unreachable(main, details) if main.all?(&:error?) && controls.all?(&:error?)
      return unreachable(main, details) if root&.error? && controls.all?(&:error?)

      if root&.rate_limited? || rate_limited?(main, root)
        return new(state: :rate_limited,
                   reason: "the origin returned HTTP 429 (Rate Limit) — the scan rate was too high or the edge is throttling",
                   control: control_summary(controls.first, root), details: details)
      end

      if root&.error?
        return new(state: :unreachable,
                   reason: "the root probe failed (#{root.error_kind}: #{Sanitize.terminal(root.error, max: 200)}) " \
                           "while other paths responded — the application is partially reachable but the root could not be assessed",
                   control: control_summary(controls.first, root), details: details)
      end

      if root&.denied?
        if controls.any?(&:denied?)
          return new(state: :blocked, reason: blocked_reason(root, controls),
                     control: control_summary(controls.find(&:denied?), root), details: details)
        end
        if controls.any?(&:not_found?)
          return new(state: :restricted,
                     reason: "the root returned HTTP #{root.status} but a random control path returned 404 — " \
                             "path-level access control, not a blanket edge block",
                     control: control_summary(controls.find(&:not_found?), root), details: details)
        end
        return new(state: :restricted,
                   reason: "the root returned HTTP #{root.status} and the control path behaved differently — " \
                           "the application is reachable but this path is protected",
                   control: control_summary(controls.first, root), details: details)
      end

      if auth_wall?(root, controls)
        return new(state: :auth_wall,
                   reason: "the site redirects to, or renders, an authentication page — PHP may exist but the surface is behind a login",
                   control: control_summary(controls.first, root), details: details)
      end

      if (catchall = controls.find { |control| soft_404?(root, control) })
        return new(state: :soft_404,
                   reason: "a random nonexistent path returned HTTP #{catchall.status} with content similar to the root — " \
                           "the server uses catch-all/soft-404 routing, so path status codes are not trustworthy",
                   control: control_summary(catchall, root), details: details)
      end

      if root&.server_error? || main.all?(&:server_error?)
        return new(state: :server_error,
                   reason: "the origin returned HTTP 5xx on the root probe — the application is unhealthy, not necessarily unpatched",
                   control: control_summary(controls.first, root), details: details)
      end

      new(state: :open, reason: "application responded normally",
          control: control_summary(controls.first, root), details: details)
    end

    def self.control?(probe)
      probe.purpose.to_s.start_with?("control")
    end

    def self.rate_limited?(main, root)
      return false unless root&.rate_limited? || main.any?(&:rate_limited?)

      main.all? { |probe| probe.error? || probe.rate_limited? }
    end

    def self.unreachable(main, details)
      first = main.find(&:error?)
      reason = if first
                 "no usable response — #{first.error_kind}: #{Sanitize.terminal(first.error, max: 200)}"
               else
                 "no usable response from the target"
               end
      new(state: :unreachable, reason: reason, details: details)
    end

    def self.blocked_reason(root, controls)
      statuses = ([root] + controls).map(&:status).compact.uniq.join("/")
      server   = ([root] + controls).map(&:server).compact.first
      bits = ["every probe, including a random control path, returned HTTP #{statuses}"]
      bits << "from #{Sanitize.header(server)}" if server
      bits << "the edge denied the scanner before the application answered"
      bits.join(" — ")
    end

    # A catch-all page can be recognised three ways: the bodies are nearly
    # identical, the title matches, or the server reflects the random
    # filename back at us. Any one is enough to stop trusting path statuses.
    def self.soft_404?(root, control)
      return false unless control&.usable? && root

      return true if control.text_body.include?(token_of(control))
      return true if control.similarity_to(root) >= 0.8

      false
    end

    def self.token_of(probe)
      path = probe.request_uri.to_s.split("?", 2).first.to_s
      File.basename(path)
    end

    def self.auth_wall?(root, controls)
      return false unless root

      # A root that redirects to, or renders, a login page is an auth wall
      # whether or not the random control path happens to 404. The control
      # path is there to catch blanket denial, not to veto the login page.
      login_response?(root)
    end

    def self.login_response?(probe)
      return false if probe.error?
      return true if probe.redirect? && probe.header("location").to_s.match?(LOGIN_PATH)
      return true if probe.title.to_s.match?(LOGIN_TEXT)
      return true if probe.text_body.match?(/<input[^>]+type=["']password["']/i)

      false
    end

    def self.control_summary(probe, root)
      return nil unless probe

      {
        path: Sanitize.url(probe.request_uri),
        status: probe.status,
        title: probe.title,
        similarity: root ? probe.similarity_to(root) : nil,
        denied: probe.denied?,
        not_found: probe.not_found?
      }
    end

    def self.stats(probes, main, controls)
      {
        probes: probes.size,
        main: main.size,
        controls: controls.size,
        usable: probes.count(&:usable?),
        denied: probes.count(&:denied?),
        not_found: probes.count(&:not_found?),
        errors: probes.count(&:error?),
        statuses: probes.map(&:status).compact.uniq.sort
      }
    end

    def open?
      state == :open
    end

    def blocked?
      state == :blocked
    end

    def restricted?
      state == :restricted
    end

    def inconclusive?
      %i[blocked restricted auth_wall rate_limited soft_404 server_error unreachable unknown].include?(state)
    end

    def label
      STATES.fetch(state, state.to_s)
    end

    def to_h
      {
        state: state,
        label: label,
        reason: reason,
        control: control,
        details: details
      }
    end
  end
end
