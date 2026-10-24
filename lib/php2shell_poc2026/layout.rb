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
  # - CJK characters are their own break opportunities and occupy two
  #   columns, so a translated report aligns the same way the English one
  #   does instead of looking like it wrapped at random
  # - a token longer than its line (a config key, a long URL) is hard-split
  #   rather than left to the terminal's soft wrap, because a soft wrap
  #   restarts at column 0 and quietly destroys the hanging indent
  # - markers (bullets, labels, weights) are never split or re-spaced —
  #   they are passed separately from the prose precisely so `split`
  #   cannot eat their leading whitespace
  module Layout
    DEFAULT_WIDTH = 80
    MIN_WIDTH     = 40
    # Long prose is hard to track even on a very wide terminal. Cap the
    # dashboard at a comfortable reading measure; 140-column lines make the
    # eye travel further than the content warrants.
    MAX_WIDTH     = 110

    TABLE_GAP = 2

    # Closing punctuation may not start a line. When the next token is one
    # of these, the current token reserves its width so the pair wraps
    # together (CJK kinsoku). Without this, a full Chinese line pushes the
    # final "。" onto a line of its own.
    CLOSING_PUNCTUATION = "。，、；：！？）〕〉》」』】”’".freeze

    # SGR sequences emitted by Style. Only the table needs to know about
    # them: prose is wrapped before styling, table cells are styled before
    # padding, so visible columns must be measured with the escapes removed.
    ANSI = /\e\[[0-9;]*m/

    # East Asian Wide/Fullwidth ranges, plus emoji. Terminals draw these in
    # two cells; counting them as one is what makes Chinese output wrap a
    # dozen columns late and tables look ragged.
    WIDE_RANGES = [
      0x1100..0x115F, 0x2329..0x232A, 0x2E80..0x303E, 0x3041..0x33FF,
      0x3400..0x4DBF, 0x4E00..0x9FFF, 0xA000..0xA4CF, 0xA960..0xA97F,
      0xAC00..0xD7A3, 0xF900..0xFAFF, 0xFE10..0xFE19, 0xFE30..0xFE6F,
      0xFF00..0xFF60, 0xFFE0..0xFFE6, 0x1B000..0x1B001,
      0x1F004..0x1F004, 0x1F0CF..0x1F0CF, 0x1F18E..0x1F18E,
      0x1F191..0x1F19A, 0x1F200..0x1F251, 0x1F300..0x1F64F,
      0x1F900..0x1F9FF, 0x1FA70..0x1FAFF, 0x20000..0x3FFFD
    ].freeze

    # Combining marks add no column of their own.
    ZERO_WIDTH = /\p{Mn}|\p{Me}/
    # Format characters (zero-width joiners, direction marks) also take no
    # cell, otherwise emoji sequences are counted several times over.
    FORMAT = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/

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

    # Length as a terminal renders it: escape sequences are free, CJK and
    # emoji are two cells, combining marks are zero.
    def self.display_width(text)
      text.to_s.gsub(ANSI, "").each_char.sum { |char| char_width(char) }
    end

    # Backwards-compatible name: callers that only need a visible length
    # outside the table should get the same width the table uses.
    def self.visible_length(text)
      display_width(text)
    end

    def self.wrap(text, limit)
      limit = [limit, 8].max
      lines = flow(text, limit)
      lines.flat_map { |line| display_width(line) <= limit ? [line] : chunk(line, limit) }
    end

    # Wrap a marker-prefixed line: `prefix` (bullet / label / weight) and
    # `text` are wrapped as one flowing paragraph, but only the prose moves
    # — the prefix stays intact at the head of the first line and
    # continuations indent to just past it.
    def self.wrap_hanging(prefix, text, hang = nil)
      hang = display_width(prefix) if hang.nil?
      w    = width
      # A hanging indent is a readability device, not a copy of the prefix.
      # Tool names and labels can be longer than half the terminal; using the
      # full prefix length would leave a one-word column and hard-split words.
      hang = [[hang, w / 2].min, 16].min
      indent = " " * hang

      lines = []
      current = prefix.dup
      current_width = display_width(current)
      pending_space = false

      units = tokens(text)
      units.each_with_index do |(token, kind), index|
        if kind == :space
          pending_space = true
          next
        end

        token_width = display_width(token)
        space = pending_space && !current.empty? && !current.end_with?(" ") ? 1 : 0
        reserve = following_punctuation_width(units, index)

        if current_width + space + token_width + reserve > w && current_width > hang
          lines << current
          current = indent.dup
          current_width = hang
          space = 0
        end

        if token_width > w - current_width
          # A single token (a URL, a file path, an unbroken CJK run in a
          # narrow column) does not fit. Fill this line to the edge and
          # continue on the indented lines instead of overflowing.
          token.each_char do |char|
            cw = char_width(char)
            if current_width + cw > w
              lines << current
              current = indent.dup
              current_width = hang
            end
            current << char
            current_width += cw
          end
        else
          if space.positive?
            current << " "
            current_width += 1
          end
          current << token
          current_width += token_width
        end

        pending_space = false
      end

      lines << current
      lines
    end

    def self.truncate(text, limit)
      text = text.to_s
      return text if display_width(text) <= limit
      return "" if limit < 1

      plain = text.gsub(ANSI, "")
      return "…" if limit == 1

      out = +""
      width = 0
      plain.each_char do |char|
        cw = char_width(char)
        break if width + cw > limit - 1

        out << char
        width += cw
      end
      out + "…"
    end

    # Pad a possibly-styled cell to its column width without counting the
    # escapes. A styled cell that overflows is stripped before truncation so
    # a report never emits half an escape sequence.
    def self.pad(text, width)
      text = text.to_s
      visible = display_width(text)
      return text + (" " * (width - visible)) if visible < width
      return text if visible == width

      truncate(text.gsub(ANSI, ""), width)
    end

    # The summary table. Only the target column (index 0) flexes — an
    # identifier keeps identifying after losing its tail, while a truncated
    # verdict or score silently becomes a different fact. When even the
    # target at its floor does not fit (a phone held upright), rows stack:
    # identifier on one line, metrics underneath, because a table that does
    # not fit is just ragged text with delusions of structure.
    def self.table(headers, rows, margin: "  ")
      return [] if rows.empty?

      usable   = width - display_width(margin)
      naturals = headers.each_index.map do |i|
        ([headers[i]] + rows.map { |r| r[i].to_s }).map { |cell| display_width(cell) }.max
      end

      widths = shrink(naturals, usable)
      return stacked(headers, rows, margin) if widths.nil?

      lines = []
      lines << margin + headers.each_index.map { |i| pad(headers[i], widths[i]) }
                     .join(" " * TABLE_GAP).rstrip
      lines << margin + widths.map { |n| "-" * n }.join(" " * TABLE_GAP).rstrip

      rows.each do |row|
        cells = row.each_index.map { |i| pad(row[i].to_s, widths[i]) }
        lines << margin + cells.join(" " * TABLE_GAP).rstrip
      end
      lines
    end

    # -- internals ---------------------------------------------------------

    def self.char_width(char)
      return 0 if char.match?(ZERO_WIDTH) || char.match?(FORMAT)

      wide?(char) ? 2 : 1
    end

    def self.wide?(char)
      code = char.ord
      WIDE_RANGES.any? { |range| range.cover?(code) }
    end

    # Break text into wrap units. Latin words stay whole; whitespace becomes
    # an explicit separator; CJK and emoji are single break opportunities so
    # a space-less Chinese sentence can wrap mid-line. The pairing of token
    # and kind keeps `wrap_hanging` from inserting spaces between Han
    # characters, which is both wrong typographically and unreadable.
    def self.tokens(text)
      result = []
      buffer = +""

      flush = lambda do
        unless buffer.empty?
          result << [buffer, :word]
          buffer = +""
        end
      end

      text.to_s.each_char do |char|
        if char.match?(/\s/)
          flush.call
          result << [" ", :space]
        elsif wide?(char) || char.match?(FORMAT)
          flush.call
          result << [char, :wide]
        else
          buffer << char
        end
      end
      flush.call
      result
    end

    # How much room the next token needs if it must not start a line. Only
    # a directly adjacent closing mark reserves space; a space before the
    # punctuation is already a legal break opportunity.
    def self.following_punctuation_width(units, index)
      nxt = units[index + 1]
      return 0 unless nxt
      return 0 if nxt[1] == :space

      closing_punctuation?(nxt[0]) ? display_width(nxt[0]) : 0
    end

    def self.closing_punctuation?(token)
      token.to_s.length == 1 && CLOSING_PUNCTUATION.include?(token)
    end

    def self.flow(text, limit)
      lines = []
      current = +""
      current_width = 0
      pending_space = false

      units = tokens(text)
      units.each_with_index do |(token, kind), index|
        if kind == :space
          pending_space = true
          next
        end

        token_width = display_width(token)
        space = pending_space && !current.empty? ? 1 : 0
        reserve = following_punctuation_width(units, index)

        if !current.empty? && current_width + space + token_width + reserve > limit
          lines << current
          current = +""
          current_width = 0
          space = 0
        end

        if token_width > limit
          token.each_char do |char|
            cw = char_width(char)
            if current_width + cw > limit
              lines << current unless current.empty?
              current = +""
              current_width = 0
            end
            current << char
            current_width += cw
          end
        else
          if space.positive?
            current << " "
            current_width += 1
          end
          current << token
          current_width += token_width
        end

        pending_space = false
      end

      lines << current unless current.empty?
      lines.empty? ? [""] : lines
    end

    def self.chunk(line, limit)
      limit = [limit, 1].max
      out = []
      current = +""
      width = 0

      line.to_s.each_char do |char|
        cw = char_width(char)
        if !current.empty? && width + cw > limit
          out << current
          current = +""
          width = 0
        end
        current << char
        width += cw
      end

      out << current unless current.empty?
      out.empty? ? [""] : out
    end

    def self.shrink(naturals, usable)
      widths = naturals.dup
      # A target truncated to eight characters is not an identifier any
      # more. Keep at least 24 columns when the URL is long enough to need
      # them; below that, stack the row instead of printing a useless stub.
      floor  = [widths[0], 24].min

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
        info = (1...row.length).map { |i| "#{headers[i]} #{row[i]}" }.join(" · ").gsub(ANSI, "")
        [margin + truncate(row[0].to_s, width - display_width(margin))] +
          wrap(info, width - display_width(indent)).map { |l| indent + l }
      end
    end

    private_class_method :char_width, :wide?, :tokens, :flow, :chunk, :shrink, :stacked,
                         :following_punctuation_width, :closing_punctuation?
  end
end
