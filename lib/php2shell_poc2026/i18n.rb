# frozen_string_literal: true

module PHP2ShellPOC2026
  # Minimal, dependency-free message catalogue. English is the canonical
  # language and stays in the source as the `default:` string, so a missing
  # translation degrades to English instead of a key name. Only the
  # human-readable text report is localised; JSON/SARIF/CSV/NDJSON keep
  # stable English messages.
  #
  # Locale resolution is deliberately boring: an explicit --lang wins, then
  # the usual POSIX variables, then the macOS user locale, then English.
  # `zh-*` maps to Simplified Chinese; unsupported languages fall back to
  # English rather than to a half-translated mix.
  module I18n
    DEFAULT_LOCALE = "en"
    SUPPORTED = %w[en zh].freeze
    PLACEHOLDER = /%\{(\w+)\}/

    class << self
      attr_reader :locale

      def locale=(value)
        @locale = normalize(value)
      end

      def normalize(value)
        text = value.to_s.strip.downcase.tr("_", "-")
        return "zh" if text == "zh" || text.start_with?("zh-")
        return "en" if text == "en" || text.start_with?("en-")

        DEFAULT_LOCALE
      end

      def supported?(value)
        SUPPORTED.include?(normalize(value))
      end

      # Order follows gettext: LC_ALL, LC_MESSAGES, LANGUAGE, LANG. An
      # explicit application variable comes first so CI and tests can pin
      # the language without touching the rest of the environment.
      def detect(env = ENV, apple_locale: nil)
        %w[PHP2SHELL_LANG LC_ALL LC_MESSAGES LANGUAGE LANG].each do |name|
          value = env[name].to_s.strip
          next if value.empty? || %w[C POSIX].include?(value)

          # LANGUAGE is a colon-separated priority list.
          candidate = value.split(":").find { |part| !part.strip.empty? }
          return normalize(candidate) if candidate
        end

        detected = apple_locale || macos_locale
        detected && !detected.empty? ? normalize(detected) : DEFAULT_LOCALE
      end

      def with_locale(value)
        previous = @locale
        @locale = normalize(value)
        yield
      ensure
        @locale = previous
      end

      # `default` is the English source string. `%{name}` placeholders are
      # replaced from `vars`; a missing variable is left visible rather than
      # raising in the middle of a report.
      def t(key, default:, **vars)
        template = translations.dig(@locale, key.to_s) || default.to_s
        interpolate(template, vars)
      end

      private

      def translations
        defined?(TRANSLATIONS) ? TRANSLATIONS : {}
      end

      def interpolate(template, vars)
        template.gsub(PLACEHOLDER) do
          name = Regexp.last_match(1).to_sym
          vars.key?(name) ? vars[name].to_s : "%{#{name}}"
        end
      end

      def macos_locale
        return nil unless RUBY_PLATFORM.include?("darwin")

        IO.popen(%w[defaults read -g AppleLocale], err: File::NULL, &:read).strip
      rescue StandardError
        nil
      end
    end

    @locale = DEFAULT_LOCALE
  end
end

require_relative "locales/zh"
