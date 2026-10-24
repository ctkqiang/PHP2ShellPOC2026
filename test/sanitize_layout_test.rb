# frozen_string_literal: true

require_relative "test_helper"

class SanitizeTest < Minitest::Test
  def test_ansi_and_control_sequences_are_removed
    text = "\e[31mred\e[0m\e]0;title\a\nnext"
    assert_equal "red next", PHP2ShellPOC2026::Sanitize.terminal(text)
  end

  def test_markdown_cell_escapes_pipe
    assert_equal "a\\|b", PHP2ShellPOC2026::Sanitize.markdown_cell("a|b")
  end

  def test_csv_quotes_commas_and_quotes
    assert_equal "\"a,b\"", PHP2ShellPOC2026::Sanitize.csv("a,b")
    assert_equal "\"a\"\"b\"", PHP2ShellPOC2026::Sanitize.csv('a"b')
  end

  def test_truncate_uses_ellipsis
    assert_equal "abcd…", PHP2ShellPOC2026::Sanitize.truncate("abcdef", 5)
  end
end

class LayoutTest < Minitest::Test
  def with_columns(value)
    old = ENV["COLUMNS"]
    ENV["COLUMNS"] = value.to_s
    yield
  ensure
    ENV["COLUMNS"] = old
  end

  def test_wrap_hanging_indents_continuations
    with_columns(50) do
      lines = PHP2ShellPOC2026::Layout.wrap_hanging("  reason    : ", "one two three four five six seven eight nine ten")
      assert_operator lines.length, :>, 1
      lines[1..].each { |line| assert line.start_with?(" " * 14), line.inspect }
    end
  end

  def test_narrow_table_stacks
    with_columns(40) do
      lines = PHP2ShellPOC2026::Layout.table(
        %w[TARGET VERDICT RISK HACK EVIDENCE],
        [["https://very-long-example.example/path", "BLOCK", "n/a UNK", "?", "0/3"]]
      )
      assert_operator lines.length, :>, 1
      assert_includes lines.join("\n"), "VERDICT"
    end
  end

  def test_chunk_handles_unicode
    with_columns(20) do
      lines = PHP2ShellPOC2026::Layout.wrap("é" * 50, 10)
      assert lines.all? { |line| line.length <= 10 }
    end
  end

  def test_long_hanging_prefix_keeps_continuations_readable
    with_columns(100) do
      lines = PHP2ShellPOC2026::Layout.wrap_hanging(
        "      Nuclei (tech-detect + custom template) — ",
        "Template-driven technology and exposure checks; write one template for the X-Powered-By floor."
      )
      assert_operator lines.length, :>=, 2
      assert_operator lines[1].strip.split.length, :>, 1
      assert lines.all? { |line| line.length <= 100 }
    end
  end

  def test_table_pads_styled_cells_by_visible_width
    with_columns(80) do
      lines = PHP2ShellPOC2026::Layout.table(
        %w[VERDICT ACCESS],
        [["\e[1;33mINCONCLUSIVE\e[0m", "BLOCK"]]
      )
      plain = lines[2].gsub(PHP2ShellPOC2026::Layout::ANSI, "")
      assert_equal lines[0].index("ACCESS"), plain.index("BLOCK")
    end
  end

  def test_stacked_table_drops_colour_instead_of_counting_escapes
    with_columns(40) do
      lines = PHP2ShellPOC2026::Layout.table(
        %w[TARGET VERDICT RISK PROBES],
        [["https://very-long-example.example/path", "\e[1;33mINCONCLUSIVE\e[0m", "n/a", "0/3"]]
      )
      refute(lines.any? { |line| line.include?("\e[") })
      assert(lines.all? { |line| line.length <= 40 })
    end
  end

  def test_display_width_counts_cjk_as_two_cells
    assert_equal 4, PHP2ShellPOC2026::Layout.display_width("中文")
    assert_equal 3, PHP2ShellPOC2026::Layout.display_width("a中")
    assert_equal 4, PHP2ShellPOC2026::Layout.display_width("\e[1m中文\e[0m")
    assert_equal 1, PHP2ShellPOC2026::Layout.display_width("e\u0301")
  end

  def test_cjk_wrap_respects_display_width
    with_columns(40) do
      lines = PHP2ShellPOC2026::Layout.wrap("被动式暴露面排查需要逐项确认", 8)
      assert_operator lines.length, :>, 1
      assert(lines.all? { |line| PHP2ShellPOC2026::Layout.display_width(line) <= 8 })
    end
  end

  def test_cjk_table_columns_line_up
    with_columns(80) do
      lines = PHP2ShellPOC2026::Layout.table(
        %w[目标 结论],
        [["https://例.test/", "存在漏洞"]]
      )
      header_index = lines[0].index("结论")
      row_index = lines[2].index("存在漏洞")
      assert_equal PHP2ShellPOC2026::Layout.display_width(lines[0][0...header_index]),
                   PHP2ShellPOC2026::Layout.display_width(lines[2][0...row_index])
      assert_equal 16, lines[1][2, 16].count("-")
    end
  end

  def test_cjk_truncate_never_splits_a_wide_character
    truncated = PHP2ShellPOC2026::Layout.truncate("中文测试", 5)
    assert_equal "中文…", truncated
    assert_operator PHP2ShellPOC2026::Layout.display_width(truncated), :<=, 5
  end

  def test_cjk_hanging_wrap_does_not_insert_spaces_between_han
    with_columns(40) do
      lines = PHP2ShellPOC2026::Layout.wrap_hanging(
        "  原因：", "被动式排查在应用代码之前读取响应头与证书信息，并据此判断暴露情况"
      )
      assert_operator lines.length, :>, 1
      assert_equal " " * PHP2ShellPOC2026::Layout.display_width("  原因："),
                   lines[1][0, PHP2ShellPOC2026::Layout.display_width("  原因：")]
      refute_includes lines[1], "中 文"
    end
  end

  def test_closing_punctuation_does_not_start_a_wrapped_line
    lines = PHP2ShellPOC2026::Layout.wrap("一二三四五六七八九。", 18)
    assert_equal ["一二三四五六七八", "九。"], lines
    refute(lines[1..].any? { |line| line.start_with?("。") })
  end
end

class StyleTest < Minitest::Test
  def test_painter_is_identity_when_disabled
    painter = PHP2ShellPOC2026::Style.painter(options(no_color: true))
    assert_equal "INCONCLUSIVE", painter.call("INCONCLUSIVE", :bold, :yellow)
  end

  def test_painter_wraps_when_enabled
    painter = PHP2ShellPOC2026::Style::Painter.new(true)
    assert_equal "\e[1;33mINCONCLUSIVE\e[0m", painter.call("INCONCLUSIVE", :bold, :yellow)
  end
end
