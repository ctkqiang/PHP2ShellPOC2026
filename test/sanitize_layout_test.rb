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
end
