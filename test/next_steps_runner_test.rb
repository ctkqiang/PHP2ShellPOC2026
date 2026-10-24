# frozen_string_literal: true

require_relative "test_helper"
require "stringio"
require "tmpdir"

class NextStepsRunnerTest < Minitest::Test
  def test_prompts_before_running_and_respects_no
    out = StringIO.new
    result = PHP2ShellPOC2026::NextStepsRunner.run(
      [], options, meta: { generated_at: "2026-10-24T00:00:00Z" },
      input: StringIO.new("n\n"), out: out
    )

    assert_nil result
    assert_includes out.string, "AUTOMATED NEXT STEPS"
    assert_includes out.string, "Proceed? [y/N]"
    refute_includes out.string, "Running safe checks"
  end

  def test_yes_runs_safe_checks_without_prompting
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        out = StringIO.new
        result = PHP2ShellPOC2026::NextStepsRunner.run(
          [], options(yes: true), meta: { generated_at: "2026-10-24T00:00:00Z" },
          input: StringIO.new, out: out
        )

        assert_equal [], result
        assert_includes out.string, "Running safe checks"
        refute_includes out.string, "Proceed? [y/N]"
        assert File.file?(File.join(dir, "php2shell.sarif"))
      end
    end
  end

  def test_command_available_is_false_for_a_missing_binary
    refute PHP2ShellPOC2026::NextStepsRunner.command_available?("definitely-not-a-real-command-xyz")
  end
end
