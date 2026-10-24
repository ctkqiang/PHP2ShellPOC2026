# frozen_string_literal: true

require "ipaddr"

module PHP2ShellPOC2026
  # Internationalised domain names, without adding a gem. `URI` only speaks
  # ASCII, so `https://münchen.de/` has to become
  # `https://xn--mnchen-3ya.de/` before Net::HTTP will touch it. This is a
  # deliberately small IDNA subset: NFC normalisation plus RFC 3492
  # Punycode. It covers the overwhelming majority of real registrations;
  # exotic IDNA2008 mappings are documented as out of scope.
  module Idn
    BASE         = 36
    TMIN         = 1
    TMAX         = 26
    SKEW         = 38
    DAMP         = 700
    INITIAL_BIAS = 72
    INITIAL_N    = 128
    DELIMITER    = "-"

    module_function

    # Returns a lower-case ASCII hostname. IPv4/IPv6 literals pass through
    # unchanged (brackets included).
    def to_ascii(host)
      text = host.to_s.strip
      return text if text.empty?
      return text if ip_literal?(text)

      trailing_dot = text.end_with?(".")
      text = text.sub(/\.\z/, "")
      labels = text.split(".", -1).map { |label| ascii_label(label) }
      result = labels.join(".")
      trailing_dot ? "#{result}." : result
    end

    def ascii_label(label)
      label = normalize(label)
      return label.downcase if label.ascii_only?

      "xn--#{encode_label(label.downcase)}"
    end

    def normalize(label)
      label.to_s.unicode_normalize(:nfc)
    rescue StandardError
      label.to_s
    end

    def ip_literal?(text)
      candidate = text.start_with?("[") && text.end_with?("]") ? text[1..-2] : text
      IPAddr.new(candidate)
      true
    rescue IPAddr::InvalidAddressError, ArgumentError
      false
    end

    # RFC 3492 section 6.3.
    def encode_label(label)
      input  = label.codepoints
      output = +""
      n      = INITIAL_N
      delta  = 0
      bias   = INITIAL_BIAS

      basic = input.select { |cp| cp < 0x80 }
      output << basic.pack("U*")
      b = basic.length
      h = basic.length
      output << DELIMITER if b.positive?

      while h < input.length
        m = input.select { |cp| cp >= n }.min
        raise ArgumentError, "invalid codepoint sequence" if m.nil?

        delta += (m - n) * (h + 1)
        n = m

        input.each do |cp|
          if cp < n
            delta += 1
          elsif cp == n
            q = delta
            k = BASE
            loop do
              t = threshold(k, bias)
              break if q < t

              output << encode_digit(t + ((q - t) % (BASE - t)))
              q = (q - t) / (BASE - t)
              k += BASE
            end
            output << encode_digit(q)
            bias = adapt(delta, h + 1, h == b)
            delta = 0
            h += 1
          end
        end

        delta += 1
        n += 1
      end

      output
    end

    def threshold(k, bias)
      if k <= bias
        TMIN
      elsif k >= bias + TMAX
        TMAX
      else
        k - bias
      end
    end

    def adapt(delta, points, first_time)
      delta = first_time ? delta / DAMP : delta / 2
      delta += delta / points

      k = 0
      while delta > ((BASE - TMIN) * TMAX) / 2
        delta /= (BASE - TMIN)
        k += BASE
      end

      k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    end

    def encode_digit(value)
      if value < 26
        (97 + value).chr
      else
        (48 + value - 26).chr
      end
    end

    # True when the host needed conversion, for the report's "display vs
    # request" note.
    def international?(host)
      !host.to_s.ascii_only?
    end
  end
end
