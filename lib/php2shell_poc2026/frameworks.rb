# frozen_string_literal: true

module PHP2ShellPOC2026
  # Framework fingerprinting is not a vanity metric: WordPress, Drupal and
  # Joomla all guarantee a large set of .php entry points, and the framework
  # version says which extra passive paths are worth checking. Detection is
  # evidence-first — a blog post mentioning WordPress is not a WordPress
  # install.
  module Frameworks
    Detection = Struct.new(:name, :confidence, :evidence, :paths, keyword_init: true) do
      def to_h
        { name: name, confidence: confidence, evidence: evidence, paths: paths }
      end
    end

    CONFIDENCE_RANK = { "high" => 3, "medium" => 2, "low" => 1 }.freeze

    module_function

    def detect(probes)
      found = {}

      probes.each do |probe|
        wordpress_evidence(probe).each { |e| add(found, "WordPress", e) }
        drupal_evidence(probe).each { |e| add(found, "Drupal", e) }
        joomla_evidence(probe).each { |e| add(found, "Joomla", e) }
        laravel_evidence(probe).each { |e| add(found, "Laravel", e) }
        symfony_evidence(probe).each { |e| add(found, "Symfony", e) }
        codeigniter_evidence(probe).each { |e| add(found, "CodeIgniter", e) }
        cakephp_evidence(probe).each { |e| add(found, "CakePHP", e) }
        yii_evidence(probe).each { |e| add(found, "Yii", e) }
        thinkphp_evidence(probe).each { |e| add(found, "ThinkPHP", e) }
        statamic_evidence(probe).each { |e| add(found, "Statamic", e) }
        craft_evidence(probe).each { |e| add(found, "Craft CMS", e) }
        magento_evidence(probe).each { |e| add(found, "Magento", e) }
        prestashop_evidence(probe).each { |e| add(found, "PrestaShop", e) }
        opencart_evidence(probe).each { |e| add(found, "OpenCart", e) }
      end

      found.map do |name, entries|
        confidence = entries.map { |e| e[:confidence] }.max_by { |c| CONFIDENCE_RANK.fetch(c, 0) }
        Detection.new(name: name, confidence: confidence,
                      evidence: entries.map { |e| e[:evidence] }.uniq,
                      paths: paths_for_name(name))
      end.sort_by { |d| [-CONFIDENCE_RANK.fetch(d.confidence, 0), d.name] }
    end

    def add(found, name, entry)
      found[name] ||= []
      found[name] << entry
    end

    def wordpress_evidence(probe)
      evidence = []
      generator = probe.generator.to_s
      evidence << high("generator meta: #{generator}") if generator.match?(/\AWordPress/i)
      evidence << high("X-Pingback points at xmlrpc.php") if probe.header("x-pingback").to_s.match?(/xmlrpc\.php/i)
      evidence << high("Link header advertises the WordPress REST API") if probe.header("link").to_s.match?(/api\.w\.org/i)
      evidence << high("cookie #{cookie_names(probe).grep(/wordpress_/i).first}") if cookie_names(probe).any? { |c| c.match?(/wordpress_|wp-settings/i) }
      if probe.text_body.match?(%r{/wp-(?:content|includes)/}i)
        evidence << medium("HTML references /wp-content/ or /wp-includes/")
      end
      if probe.request_uri.to_s.match?(%r{/wp-login\.php}i) && probe.ok? &&
         probe.text_body.match?(/wp-submit|wordpress/i)
        evidence << high("/wp-login.php returned a WordPress login form")
      end
      evidence
    end

    def drupal_evidence(probe)
      evidence = []
      generator = probe.generator.to_s
      evidence << high("generator meta: #{generator}") if generator.match?(/Drupal/i)
      evidence << high("X-Generator: Drupal") if probe.header("x-generator").to_s.match?(/Drupal/i)
      evidence << medium("Drupal.settings in page source") if probe.text_body.match?(/Drupal\.settings/i)
      evidence << medium("/sites/default/files/ in page source") if probe.text_body.match?(%r{/sites/default/files/}i)
      evidence
    end

    def joomla_evidence(probe)
      evidence = []
      generator = probe.generator.to_s
      evidence << high("generator meta: #{generator}") if generator.match?(/Joomla/i)
      evidence << medium("/media/system/js/ in page source") if probe.text_body.match?(%r{/media/system/js/}i)
      evidence << medium("option=com_ in page source") if probe.text_body.match?(/option=com_/i)
      evidence << high("joomla_ cookie") if cookie_names(probe).any? { |c| c.match?(/joomla_/i) }
      evidence
    end

    def laravel_evidence(probe)
      evidence = []
      evidence << high("laravel_session cookie") if cookie_names(probe).any? { |c| c.match?(/laravel_session/i) }
      evidence << medium("XSRF-TOKEN cookie alongside a PHP session") if cookie_names(probe).any? { |c| c.match?(/XSRF-TOKEN/i) } && probe.php_cookie?
      evidence
    end

    def symfony_evidence(probe)
      evidence = []
      evidence << high("symfony cookie") if cookie_names(probe).any? { |c| c.match?(/\Asymfony/i) }
      evidence << high("X-Debug-Token header") if probe.header("x-debug-token")
      evidence
    end

    def codeigniter_evidence(probe)
      evidence = []
      evidence << high("ci_session cookie") if cookie_names(probe).any? { |c| c.match?(/\Aci_session/i) }
      evidence
    end

    def cakephp_evidence(probe)
      evidence = []
      evidence << high("CAKEPHP cookie") if cookie_names(probe).any? { |c| c.match?(/\ACAKEPHP/i) }
      evidence
    end

    def yii_evidence(probe)
      evidence = []
      evidence << high("YII_CSRF_TOKEN cookie") if cookie_names(probe).any? { |c| c.match?(/YII_CSRF_TOKEN/i) }
      evidence
    end

    def thinkphp_evidence(probe)
      evidence = []
      evidence << high("X-Powered-By: ThinkPHP") if probe.header("x-powered-by").to_s.match?(/ThinkPHP/i)
      evidence << high("think_ cookie") if cookie_names(probe).any? { |c| c.match?(/\Athink_/i) }
      evidence
    end

    def statamic_evidence(probe)
      evidence = []
      evidence << high("X-Powered-By: Statamic") if probe.header("x-powered-by").to_s.match?(/Statamic/i)
      evidence << high("statamic cookie") if cookie_names(probe).any? { |c| c.match?(/\Astatamic/i) }
      evidence
    end

    def craft_evidence(probe)
      evidence = []
      evidence << high("X-Powered-By: Craft CMS") if probe.header("x-powered-by").to_s.match?(/Craft CMS/i)
      evidence << high("CraftSessionId cookie") if cookie_names(probe).any? { |c| c.match?(/\ACraftSessionId/i) }
      evidence
    end

    def magento_evidence(probe)
      evidence = []
      evidence << high("X-Powered-By: Magento") if probe.header("x-powered-by").to_s.match?(/Magento/i)
      evidence << high("mage-cache-sessid cookie") if cookie_names(probe).any? { |c| c.match?(/\Amage-cache-sessid/i) }
      evidence
    end

    def prestashop_evidence(probe)
      evidence = []
      evidence << high("X-Powered-By: PrestaShop") if probe.header("x-powered-by").to_s.match?(/PrestaShop/i)
      evidence << high("PrestaShop cookie") if cookie_names(probe).any? { |c| c.match?(/\APrestaShop-/i) }
      evidence
    end

    def opencart_evidence(probe)
      evidence = []
      evidence << high("OCSESSID cookie") if cookie_names(probe).any? { |c| c.match?(/\AOCSESSID/i) }
      evidence
    end

    def cookie_names(probe)
      probe.set_cookies.map { |cookie| cookie.to_s.split(";", 2).first.to_s.split("=", 2).first.to_s }
    end

    def high(text)
      { confidence: "high", evidence: text }
    end

    def medium(text)
      { confidence: "medium", evidence: text }
    end

    def paths_for_name(name)
      case name
      when "WordPress" then %w[/wp-login.php /wp-json/ /xmlrpc.php]
      when "Drupal"    then %w[/core/install.php]
      when "Joomla"    then %w[/administrator/]
      else                  %w[/index.php]
      end
    end

    # Passive version hints from pages we already fetched. These are
    # framework versions, not PHP versions — useful context, never used to
    # infer the interpreter patch level.
    def version_hints(probes)
      hints = []
      probes.each do |probe|
        generator = probe.generator.to_s
        if (match = generator.match(/\AWordPress\s+([\d.]+)/i))
          hints << { name: "WordPress", version: match[1], source: "generator meta" }
        elsif (match = generator.match(/\ADrupal\s+([\d.]+)/i))
          hints << { name: "Drupal", version: match[1], source: "generator meta" }
        elsif (match = generator.match(/\AJoomla!?\s*([\d.]+)/i))
          hints << { name: "Joomla", version: match[1], source: "generator meta" }
        end

        if probe.request_uri.to_s.match?(/joomla\.xml/i) &&
           (match = probe.text_body.match(%r{<version>\s*([\d.]+)\s*</version>}i))
          hints << { name: "Joomla", version: match[1], source: "joomla.xml" }
        end

        if probe.request_uri.to_s.match?(/CHANGELOG\.txt/i) &&
           (match = probe.text_body.match(/\ADrupal\s+([\d.]+)/i))
          hints << { name: "Drupal", version: match[1], source: "CHANGELOG.txt" }
        end
      end
      hints.uniq
    end

    def primary(detections)
      detections.first && detections.first.name
    end

    def to_h(detections)
      detections.map(&:to_h)
    end
  end
end
