# frozen_string_literal: true

module PHP2ShellPOC2026
  # Politeness is part of the tool's contract. One limiter is shared by all
  # worker threads, keyed by host, so `--threads 8` does not accidentally
  # turn into eight simultaneous requests against one origin.
  class RateLimiter
    def initialize(delay_ms)
      @delay_ms = delay_ms.to_i
      @next_at  = {}
      @mutex    = Mutex.new
    end

    def wait(host)
      return if @delay_ms <= 0

      key  = host.to_s.downcase
      wait = @mutex.synchronize do
        now = monotonic
        at  = @next_at[key] || now
        @next_at[key] = [at, now].max + (@delay_ms / 1000.0)
        [at - now, 0.0].max
      end

      sleep(wait) if wait.positive?
    end

    private

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
