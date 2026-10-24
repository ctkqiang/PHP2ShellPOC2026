# frozen_string_literal: true

require_relative "../i18n"
require_relative "../layout"
require_relative "../sanitize"
require_relative "../style"

module PHP2ShellPOC2026
  module Poc
    # Human-readable presentation for the POC. The exploit itself produces
    # addresses, offsets and multipart counters; this class turns those into
    # short progress lines so the operator can see what is happening while a
    # 12 MB upload or a worker recycle is in flight.
    class Console
      attr_reader :options

      def initialize(options:, out: $stdout)
        @options = options
        @out = out
        @paint = Style.painter(options)
      end

      def warning(text)
        blank
        title = I18n.t("data.poc.warning_title", default: "AUTHORIZED USE ONLY")
        @out.puts "  #{@paint.call(title, :bold, :yellow)}"
        @out.puts "  #{'-' * [Layout.width - 4, 20].max}"
        text.to_s.split(/\n{2,}/).each do |paragraph|
          Layout.wrap(paragraph.gsub(/\s+/, " ").strip, Layout.width - 4).each do |line|
            @out.puts "  #{line}"
          end
          blank
        end
      end

      def title(text)
        blank
        @out.puts "  #{@paint.call(text, :bold, :cyan)}"
      end

      def step(number, total, title, detail: nil)
        blank
        @out.puts "  #{@paint.call("[#{number}/#{total}]", :bold, :cyan)} #{@paint.call(title, :bold)}"
        info(detail) if detail
      end

      def action(text)
        line("→", text, :cyan)
      end

      def response(text)
        line("←", text, :dim)
      end

      def success(text)
        line("✓", text, :green)
      end

      def failure(text)
        line("✗", text, :red)
      end

      def info(text)
        line("·", text, :dim)
      end

      def technical(text)
        return unless @options.respond_to?(:verbose) && @options.verbose

        line("·", text, :dim)
      end

      def log_line(text)
        line("│", text, :dim)
      end

      def question(text)
        @out.print "  #{@paint.call('?', :bold, :cyan)} #{text}"
        @out.flush if @out.respond_to?(:flush)
      end

      def blank
        @out.puts unless @out.respond_to?(:string) && @out.string.end_with?("\n\n")
      end

      private

      def line(marker, text, colour)
        prefix = "      #{@paint.call(marker, colour)} "
        Layout.wrap_hanging(prefix, Sanitize.terminal(text), 8).each { |line| @out.puts line }
      end
    end
  end
end
