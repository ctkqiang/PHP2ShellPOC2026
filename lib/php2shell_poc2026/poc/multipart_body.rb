# frozen_string_literal: true

module PHP2ShellPOC2026
  module Poc
    # Byte-exact multipart/form-data construction. Hash keys are deliberately
    # symbols and the result is always ASCII-8BIT so binary cookies and forged
    # structures survive the round trip.
    module MultipartBody
      module_function

      def build(parts, boundary)
        boundary = boundary.to_s.b
        body = +"".b
        parts.each do |part|
          name = part.fetch(:name).to_s.b
          data = part.fetch(:data).to_s.b
          filename = part[:filename]

          body << "--" << boundary << "\r\n"
          body << 'Content-Disposition: form-data; name="' << name << '"'
          if filename
            body << '; filename="' << filename.to_s.b << '"'
            body << "\r\nContent-Type: application/octet-stream"
          end
          body << "\r\n\r\n" << data << "\r\n"
        end
        body << "--" << boundary << "--\r\n"
        body
      end

      def field(name, data, filename: nil)
        { name: name, data: data, filename: filename }
      end
    end
  end
end
