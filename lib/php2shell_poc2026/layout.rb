# frozen_string_literal: true

require "io/console"

module PHP2ShellPOC2026
  # Terminal geometry. Every line the text report prints passes through here,
  # so one report is readable on a 40-column phone terminal and a
  # 140-column desktop without the reader fighting soft wraps.
  #
  # Width resolution order: an explicit COLUMNS (so CI, tests and users can
  # force a width), then the controlling terminal, then a conservative 80.
  #
  # Wrapping rules, in one place because they are easy to get subtly wrong:
  # - greedy word wrap on spaces; no hyphenation, no embedded newlines
  # - a token longer than its line (a config key, a long URL) is hard-split
  #   rather than left to the terminal's soft wrap, because a soft wrap
  #   restarts at column 0 and quietly destroys the hanging indent
  # - markers (bullets, labels, weights) are never split or re-spaced —
  #   they are passed separately from the prose precisely so `split`
  #   cannot eat their leading whitespace
  module Layout
    DEFAULT_WIDTH = 80
    MIN_WIDTH     = 40
    MAX_WIDTH     = 140

    TABLE_GAP = 2

    def self.width
      w = ENV["COLUMNS"].to_i
      w = terminal_width if w <= 0
      w = DEFAULT_WIDTH if w <= 0
      w.clamp(MIN_WIDTH, MAX_WIDTH)
    end

    # The controlling terminal's columns, when there is one. Piped output
    # and CI jobs have none, which is exactly when COLUMNS or the default
    # should win — a log file does not care how wide the screen is.
    def self.terminal_width
      console = IO.console
      console ? console.winsize[1] : 0
    rescue StandardError
      0
    end

    def self.wrap(text, limit)
      limit = [limit, 8].max
      greedy(text, limit).flat_map { |line| line.length <= limit ? [line] : chunk(line, limit) }
    end

    # Wrap a marker-prefixed line: `prefix` (bullet / label / weight) and
    # `text` are wrapped as one flowing paragraph, but only the prose moves
    # — the prefix stays intact at the head of the first line and
    # continuations indent to just past it.
    def self.wrap_hanging(prefix, text, hang = nil)
      hang = prefix.length if hang.nil?
      w    = width
      cont = [w - hang, 8].max

      lines = greedy_hanging(prefix, text, w, cont)
      lines.each_with_index.flat_map do |line, i|
        limit = i.zero? ? w : cont
        line.length <= limit ? [line] : chunk(line, cont)
      end
    end

    def self.truncate(text, limit)
      text = text.to_s
      return text if text.length <= limit
      return "" if limit < 1
      return "…" if limit == 1

      text[0, limit - 1] + "…"
    end

    # The summary table. Only the target column (index 0) flexes — an
    # identifier keeps identifying after losing its tail, while a truncated
    # verdict or score silently becomes a different fact. When even the
    # target at its floor does not fit (a phone held upright), rows stack:
    # identifier on one line, metrics underneath, because a table that does
    # not fit is just ragged text with delusions of structure.
    def self.table(headers, rows, margin: "  ")
      return [] if rows.empty?

      usable   = width - margin.length
      naturals = headers.each_index.map do |i|
        ([headers[i]] + rows.map { |r| r[i].to_s }).map(&:length).max
      end

      widths = shrink(naturals, usable)
      return stacked(headers, rows, margin) if widths.nil?

      lines = []
      lines << margin + headers.each_index.map { |i| headers[i].ljust(widths[i]) }
                     .join(" " * TABLE_GAP).rstrip
      lines << margin + widths.map { |n| "-" * n }.join(" " * TABLE_GAP).rstrip

      rows.each do |row|
        cells = row.each_index.map do |i|
          truncate(row[i].to_s, widths[i]).ljust(widths[i])
        end
        lines << margin + cells.join(" " * TABLE_GAP).rstrip
      end
      lines
    end

    # -- internals ---------------------------------------------------------

    def self.greedy(text, limit)
      lines = []
      current = +""

      text.to_s.split(" ").each do |word|
        if current.empty?
          current = word
        elsif current.length + 1 + word.length <= limit
          current << " " << word
        else
          lines << current
          current = word.dup
        end
      end

      lines << current unless current.empty?
      lines.empty? ? [""] : lines
    end

    def self.greedy_hanging(prefix, text, first_limit, cont_limit)
      lines   = []
      current = prefix.dup
      limit   = first_limit

      text.to_s.split(" ").each do |word|
        if current.match?(/\s\z/)
          current << word
        elsif current.length + 1 + word.length <= limit
          current << " " << word
        else
          lines << current
          current = word.dup
          limit   = cont_limit
        end
      end

      lines << current
      lines
    end

    def self.chunk(line, limit)
      line.scan(/.{1,#{limit}}/)
    end

    def self.shrink(naturals, usable)
      widths = naturals.dup
      floor  = [widths[0], 8].min

      loop do
        total = widths.sum + TABLE_GAP * (widths.length - 1)
        return widths if total <= usable
        return nil if widths[0] <= floor

        widths[0] -= 1
      end
    end

    def self.stacked(headers, rows, margin)
      rows.flat_map do |row|
        indent = margin + "  "
        info = (1...row.length).map { |i| "#{headers[i]} #{row[i]}" }.join(" · ")
        [margin + truncate(row[0].to_s, width - margin.length)] +
          wrap(info, width - indent.length).map { |l| indent + l }
      end
    end

    private_class_method :greedy, :greedy_hanging, :chunk, :shrink, :stacked
  end
end
