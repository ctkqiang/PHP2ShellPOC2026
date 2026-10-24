# frozen_string_literal: true

module PHP2ShellPOC2026
  # A per-scan, thread-local record of what was actually sent and received.
  # Kept out of Scanner instance state so parallel target scans cannot
  # interleave each other's evidence.
  class Trace
    def initialize(enabled: false)
      @enabled = enabled
      @lines   = []
      @mutex   = Mutex.new
    end

    def add(line)
      return unless @enabled

      @mutex.synchronize { @lines << line.to_s }
      nil
    end

    alias << add

    def lines
      @mutex.synchronize { @lines.dup }
    end

    def enabled?
      @enabled
    end

    def empty?
      lines.empty?
    end
  end
end
