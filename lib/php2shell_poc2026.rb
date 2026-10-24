# frozen_string_literal: true

# Single entry point for the library. Everything the tool knows how to do
# sits behind this one require, so callers — the CLI, a test file, someone's
# own script — get the whole surface with a single line and no ordering
# puzzles of their own to solve.

require "openssl"

require_relative "php2shell_poc2026/version"
require_relative "php2shell_poc2026/errors"
require_relative "php2shell_poc2026/i18n"
require_relative "php2shell_poc2026/sanitize"
require_relative "php2shell_poc2026/idn"
require_relative "php2shell_poc2026/target"
require_relative "php2shell_poc2026/scope"
require_relative "php2shell_poc2026/options"
require_relative "php2shell_poc2026/trace"
require_relative "php2shell_poc2026/rate_limiter"
require_relative "php2shell_poc2026/probe"
require_relative "php2shell_poc2026/http_client"
require_relative "php2shell_poc2026/access"
require_relative "php2shell_poc2026/frameworks"
require_relative "php2shell_poc2026/discovery"
require_relative "php2shell_poc2026/dns_info"
require_relative "php2shell_poc2026/block_page"
require_relative "php2shell_poc2026/environment"
require_relative "php2shell_poc2026/verdict"
require_relative "php2shell_poc2026/risk"
require_relative "php2shell_poc2026/hackability"
require_relative "php2shell_poc2026/attack"
require_relative "php2shell_poc2026/detections"
require_relative "php2shell_poc2026/remediation"
require_relative "php2shell_poc2026/red_team"
require_relative "php2shell_poc2026/tooling"
require_relative "php2shell_poc2026/next_actions"
require_relative "php2shell_poc2026/next_steps_runner"
require_relative "php2shell_poc2026/scan_result"
require_relative "php2shell_poc2026/scanner"
require_relative "php2shell_poc2026/summary"
require_relative "php2shell_poc2026/layout"
require_relative "php2shell_poc2026/style"
require_relative "php2shell_poc2026/report"
require_relative "php2shell_poc2026/cli"

module PHP2ShellPOC2026
end
