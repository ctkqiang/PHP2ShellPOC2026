# frozen_string_literal: true

require "cgi"

module PHP2ShellPOC2026
  # Everything printed by this tool that originated from a target is
  # untrusted. A malicious host can put ANSI escapes, OSC title sequences,
  # bidi overrides or CR/LF in a header and turn a terminal report into a
  # terminal exploit. Sanitising at the boundary is cheaper than auditing
  # every interpolation site later.
  module Sanitize
    ANSI_CSI   = /\e\[[0-9;?]*[ -\/]*[@-~]/
    ANSI_OSC   = /\e\][^\a\e]*(?:\a|\e\\)/
    ANSI_OTHER = /\e[@-_]/
    CONTROL    = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/
    BIDI       = /[\u202A-\u202E\u2066-\u2069]/
    ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/

    module_function

    # Convert arbitrary bytes into a single safe UTF-8 line. Newlines and
    # tabs collapse to spaces because a report field is one field, not a
    # document.
    def terminal(value, max: nil)
      text = utf8(value)
      text = text.gsub(ANSI_OSC, "")
                 .gsub(ANSI_CSI, "")
                 .gsub(ANSI_OTHER, "")
                 .gsub(CONTROL, " ")
                 .gsub(BIDI, "")
                 .gsub(ZERO_WIDTH, "")
                 .tr("\t\r\n", "   ")
                 .gsub(/\s+/, " ")
                 .strip
      max ? truncate(text, max) : text
    end

    # Header values must never carry CR/LF onwards. Strip rather than reject
    # so a hostile response cannot crash the report renderer.
    def header(value, max: 300)
      terminal(value, max: max)
    end

    # URLs are target-derived too. Keep the characters that make a URL
    # readable while removing control sequences.
    def url(value, max: nil)
      terminal(value, max: max)
    end

    # HTML escaping for Markdown/HTML reports; target text may contain tags.
    def html(value)
      CGI.escapeHTML(terminal(value))
    end

    # A Markdown table cell must not contain a raw pipe or newline.
    def markdown_cell(value)
      terminal(value).gsub("\\", "\\\\\\\\").gsub("|", "\\|")
    end

    # CSV quoting without pulling in the csv gem (which is a bundled gem on
    # newer Rubies and would add an install-time dependency for no gain).
    def csv(value)
      text = terminal(value)
      if text.include?(",") || text.include?('"') || text.include?("\n")
        "\"#{text.gsub('"', '""')}\""
      else
        text
      end
    end

    # Force arbitrary bytes into valid UTF-8 without raising. Used before
    # every regex against a response body, because a malformed byte in a
    # header or body should not take down a scan.
    def utf8(value)
      text = value.to_s
      return text if text.encoding == Encoding::UTF_8 && text.valid_encoding?

      text.dup.force_encoding(Encoding::UTF_8).scrub("?")
    rescue StandardError
      value.to_s.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "?")
    end

    # Decode a response body using the charset the server declared, then
    # scrub. French, Japanese and Windows-1252 sites all serve non-UTF-8
    # without saying so sometimes; a scanner should not fall over.
    def decode_body(bytes, charset)
      raw = bytes.to_s.dup.force_encoding(Encoding::BINARY)
      return utf8(raw) if charset.nil? || charset.empty?

      encoded = Encoding.find(charset)
      raw.force_encoding(encoded).encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "?")
    rescue ArgumentError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
      utf8(raw)
    end

    def truncate(value, max)
      text = value.to_s
      return text if max.nil? || text.length <= max
      return "" if max < 1
      return "…" if max == 1

      text[0, max - 1] + "…"
    end

    # Collapse a body excerpt into something a human can read in a report.
    # Used only when --evidence is passed.
    def excerpt(value, max: 512)
      terminal(value, max: max)
    end
  end
end
