# frozen_string_literal: true

module PHP2ShellPOC2026
  module Poc
    # Reads the small KEY=0x... file produced by the lab helper for a
    # particular libphp build. The POC has no command-line flags; if the file
    # is absent the bookworm/lab defaults are used.
    module OffsetTable
      KEYS = {
        "ZIF_OFFSET" => :system_function,
        "DTOR_OFFSET" => :destructor,
        "HTDATA_OFFSET" => :carrier
      }.freeze

      module_function

      def load(path = File.expand_path("out/offsets.env", Dir.pwd))
        return {} unless path && File.file?(path)

        File.readlines(path, chomp: true).each_with_object({}) do |line, result|
          text = line.strip
          next if text.empty? || text.start_with?("#") || !text.include?("=")

          key, value = text.split("=", 2)
          mapped = KEYS[key.strip]
          next unless mapped

          begin
            result[mapped] = Integer(value.strip, 0)
          rescue ArgumentError, TypeError
            next
          end
        end
      rescue SystemCallError
        {}
      end
    end
  end
end
