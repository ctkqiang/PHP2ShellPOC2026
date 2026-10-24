# frozen_string_literal: true

require_relative "../i18n"
require_relative "../sanitize"
require_relative "console"

module PHP2ShellPOC2026
  module Poc
    # Prints the final POC card. The progress lines are emitted by the
    # runner; this is the short answer: did the proof command run, how long
    # did it take, and — with -v — what addresses and error code did the
    # exploit actually produce?
    class Presenter
      def initialize(result, options:, out: $stdout, console: nil)
        @result = result
        @options = options
        @out = out
        @console = console || Console.new(options: options, out: out)
      end

      def render
        I18n.with_locale(@options.locale) do
          print_verdict
          print_attempts
          print_technical
          @console.blank
        end
      end

      private

      def print_verdict
        if @result.confirmed?
          @console.title(Poc.t("presenter.confirmed_title", "PENETRATION TEST — CONFIRMED"))
          @console.success(Poc.t("presenter.result_success",
                                 "RESULT: SUCCESS — the proof command ran on the target."))
          unless @result.proof.to_s.empty?
            @console.info(Poc.t("presenter.proof", "Proof: %{proof}",
                                proof: Sanitize.terminal(@result.proof.to_s, max: 300)))
          end
        else
          @console.title(Poc.t("presenter.failed_title", "PENETRATION TEST — FAILED"))
          @console.failure(Poc.t("presenter.result_failed",
                                 "RESULT: FAILED — no proof was observed."))
          unless @result.error.to_s.empty?
            @console.info(Poc.t("presenter.reason", "Reason: %{reason}",
                                reason: Poc.failure_text(@result.error)))
          end
        end
      end

      def print_attempts
        attempts = @result.attempts || {}
        @console.info(Poc.t("presenter.attempts",
                            "Attempts: heap %{heap}/3 · library %{library}/3 · command %{command}/5",
                            heap: attempts[:heap].to_i,
                            library: attempts[:library].to_i,
                            command: attempts[:command].to_i))
        @console.info(Poc.t("presenter.duration", "Duration: %{duration}",
                            duration: format_duration(@result.duration_ms)))
      end

      def print_technical
        return unless @options.respond_to?(:verbose) && @options.verbose

        @console.info(Poc.t("presenter.technical_title", "Technical details:"))
        @console.technical(Poc.t("presenter.technical_status",
                                 "Status: %{status}", status: @result.status))
        unless @result.error.to_s.empty?
          @console.technical(Poc.t("presenter.technical_error",
                                   "Error code: %{error}", error: @result.error))
        end
        @console.technical(Poc.t("presenter.technical_heap",
                                 "Heap anchor: %{value}", value: hex(@result.heap_anchor)))
        @console.technical(Poc.t("presenter.technical_library",
                                 "Library base: %{value}", value: hex(@result.library_anchor)))
        @console.technical(Poc.t("presenter.technical_carrier",
                                 "Carrier address: %{value}", value: hex(@result.carrier_address)))
        @console.technical(Poc.t("presenter.technical_system",
                                 "system() address: %{value}", value: hex(@result.system_function)))

        entries = Array(@result.log)
        return if entries.empty?

        @console.info(Poc.t("presenter.technical_log_title", "Output log:"))
        entries.each { |entry| @console.log_line(entry) }
      end

      def hex(value)
        number = value.to_i
        number.positive? ? format("0x%x", number) : unavailable
      end

      def unavailable
        Poc.t("presenter.unavailable", "unavailable")
      end

      def format_duration(ms)
        ms = ms.to_f
        ms < 1000 ? format("%.0f ms", ms) : format("%.2f s", ms / 1000.0)
      end
    end
  end
end
