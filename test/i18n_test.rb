# frozen_string_literal: true

require_relative "test_helper"

class I18nTest < Minitest::Test
  def test_normalize_maps_chinese_variants
    %w[zh zh-CN zh_CN zh_CN.UTF-8 zh-TW].each do |value|
      assert_equal "zh", PHP2ShellPOC2026::I18n.normalize(value), value
    end
  end

  def test_normalize_maps_english_and_falls_back
    assert_equal "en", PHP2ShellPOC2026::I18n.normalize("en_US.UTF-8")
    assert_equal "en", PHP2ShellPOC2026::I18n.normalize("fr_FR.UTF-8")
    assert_equal "en", PHP2ShellPOC2026::I18n.normalize(nil)
  end

  def test_detect_prefers_application_variable
    env = { "PHP2SHELL_LANG" => "zh_CN.UTF-8", "LC_ALL" => "en_US.UTF-8", "LANG" => "en_US.UTF-8" }
    assert_equal "zh", PHP2ShellPOC2026::I18n.detect(env, apple_locale: "en_US")
  end

  def test_detect_skips_c_locale_and_honours_language_list
    env = { "LC_ALL" => "C", "LANG" => "POSIX", "LANGUAGE" => "zh_CN:en_US" }
    assert_equal "zh", PHP2ShellPOC2026::I18n.detect(env, apple_locale: "en_US")

    env = { "LC_ALL" => "C", "LANG" => "zh_CN.UTF-8" }
    assert_equal "zh", PHP2ShellPOC2026::I18n.detect(env, apple_locale: "en_US")
  end

  def test_detect_uses_macos_locale_then_english
    assert_equal "zh", PHP2ShellPOC2026::I18n.detect({}, apple_locale: "zh-Hans-CN")
    assert_equal "en", PHP2ShellPOC2026::I18n.detect({}, apple_locale: "en_US")
    assert_equal "en", PHP2ShellPOC2026::I18n.detect({ "LANG" => "de_DE.UTF-8" }, apple_locale: "en_US")
  end

  def test_translation_and_english_fallback
    PHP2ShellPOC2026::I18n.locale = "zh"
    assert_equal "存在漏洞",
                 PHP2ShellPOC2026::I18n.t("text.verdict.vulnerable", default: "VULNERABLE")
    assert_equal "Untranslated 7",
                 PHP2ShellPOC2026::I18n.t("test.not_in_catalogue", default: "Untranslated %{n}", n: 7)
    assert_equal "keeps %{missing}",
                 PHP2ShellPOC2026::I18n.t("test.not_in_catalogue", default: "keeps %{missing}")
  end

  def test_with_locale_restores_previous_locale
    PHP2ShellPOC2026::I18n.locale = "en"
    observed = PHP2ShellPOC2026::I18n.with_locale("zh") { PHP2ShellPOC2026::I18n.locale }
    assert_equal "zh", observed
    assert_equal "en", PHP2ShellPOC2026::I18n.locale
  end
end
