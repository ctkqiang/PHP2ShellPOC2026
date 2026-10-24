# frozen_string_literal: true

module PHP2ShellPOC2026
  # ANSI styling for the human-readable report. Colour is a readability aid,
  # never information: every meaning it carries is also present in the text,
  # so a pipe, a log file or a colour-blind reader loses nothing.
  #
  # Colour is opt-in by context, not by default: it is emitted only when
  # stdout is a terminal, the report is not being written with --output and
  # the user has not set --no-color or NO_COLOR. That keeps redirects, CI
  # logs, golden-file tests and machine formats free of escape sequences.
  module Style
    RESET = "\e[0m"

    CODES = {
      bold: 1,
      dim: 2,
      italic: 3,
      red: 31,
      green: 32,
      yellow: 33,
      blue: 34,
      magenta: 35,
      cyan: 36
    }.freeze

    VERDICT_COLOURS = {
      vulnerable: %i[bold red],
      eol: %i[bold red],
      patched: %i[bold green],
      no_php: %i[bold green],
      unknown: %i[bold yellow],
      inconclusive: %i[bold yellow]
    }.freeze

    ACCESS_COLOURS = {
      open: %i[bold green],
      blocked: %i[bold yellow],
      restricted: %i[bold yellow],
      auth_wall: %i[bold yellow],
      rate_limited: %i[bold yellow],
      soft_404: %i[bold yellow],
      server_error: %i[bold red],
      unreachable: %i[bold red],
      unknown: %i[dim]
    }.freeze

    def self.enabled?(options)
      return false if options.respond_to?(:no_color) && options.no_color
      return false if options.respond_to?(:output) && options.output
      return false if ENV["NO_COLOR"] && !ENV["NO_COLOR"].empty?
      return false unless $stdout.respond_to?(:tty?) && $stdout.tty?

      true
    end

    def self.painter(options)
      Painter.new(enabled?(options))
    end

    # A tiny wrapper so callers never have to think about reset codes. When
    # disabled every method is the identity function.
    class Painter
      def initialize(enabled)
        @enabled = enabled
      end

      def enabled?
        @enabled
      end

      def call(text, *styles)
        return text.to_s unless @enabled
        return text.to_s if styles.empty?

        codes = styles.map { |style| CODES.fetch(style) }
        "\e[#{codes.join(';')}m#{text}#{RESET}"
      end

      def verdict(status)
        call(status.to_s, *VERDICT_COLOURS.fetch(status, []))
      end

      def access(state)
        call(state.to_s, *ACCESS_COLOURS.fetch(state, []))
      end
    end
  end
end
