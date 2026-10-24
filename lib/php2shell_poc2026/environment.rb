# frozen_string_literal: true

require_relative "block_page"
require_relative "frameworks"
require_relative "i18n"
require_relative "sanitize"

module PHP2ShellPOC2026
  # What sits in front of PHP shapes both exploit reliability and which
  # controls can realistically stop it: mod_php makes an exploit one-shot,
  # FPM makes it a coin flip on worker affinity, a WAF decides whether the
  # blue-team notes are already covered or aspirational.
  #
  # Everything here is inferred from response headers and error bodies
  # alone. Active fingerprinting of someone else's edge is a conversation
  # with their SOC, not their application, and this tool does not start it.
  class Environment
    attr_reader :server, :via, :edge, :cdn, :waf, :hosting, :sapi,
                :sapi_rationale, :frameworks, :framework_versions, :tls,
                :dns, :access, :block_page

    def initialize(probes, access:, tls: nil, dns: nil, surface: {})
      @probes      = probes
      @access      = access
      @tls         = tls
      @dns         = dns
      @surface     = surface
      @headers     = aggregate_headers(probes)
      @server      = header("server")
      @via         = header("via")
      @edge        = detect_edge
      @cdn         = detect_cdn
      @block_page  = BlockPage.analyze(probes, access: access)
      @waf         = detect_waf
      @hosting     = detect_hosting
      @frameworks  = Frameworks.detect(probes)
      @framework_versions = Frameworks.version_hints(probes)
      @sapi, @sapi_rationale = detect_sapi
    end

    def cdn?
      !cdn.nil?
    end

    def waf?
      !waf.nil?
    end

    def php_detected?
      @surface[:php_detected] || @probes.any? { |probe| !probe.php_markers.empty? }
    end

    def to_h
      {
        server: server && Sanitize.header(server),
        via: via && Sanitize.header(via),
        edge: edge,
        cdn: cdn,
        waf: waf,
        hosting: hosting,
        sapi: sapi,
        sapi_rationale: sapi_rationale,
        frameworks: frameworks.map(&:to_h),
        framework_versions: framework_versions,
        tls: tls,
        dns: dns,
        block_page: block_page&.to_h,
        access: access.to_h
      }
    end

    private

    def aggregate_headers(probes)
      usable = probes.reject(&:error?)
      usable = probes if usable.empty?
      usable.each_with_object({}) do |probe, acc|
        probe.headers.each do |name, value|
          acc[name.to_s.downcase] ||= value
        end
      end
    end

    def header(name)
      value = @headers[name]
      value && Sanitize.header(value)
    end

    def header_name?(pattern)
      @headers.keys.any? { |name| name.match?(pattern) }
    end

    def bodies
      @probes.select(&:textual?).map { |probe| probe.text_body[0, 4096].to_s }.join("\n")
    end

    def detect_edge
      server = @server.to_s.downcase
      return "openresty" if server.include?("openresty")
      return "cloudflare" if server.include?("cloudflare")
      return "akamai" if server.include?("akamaighost")
      return "litespeed" if server.include?("litespeed")
      return "nginx" if server.include?("nginx")
      return "apache" if server.include?("apache")
      return "iis" if server.include?("microsoft-iis") || server.include?("iis")
      return "envoy" if server.include?("envoy")
      return "caddy" if server.include?("caddy")
      return "traefik" if server.include?("traefik")
      return "haproxy" if server.include?("haproxy")
      return "varnish" if header("x-varnish")
      return "kong" if header_name?(/\Ax-kong-/)
      return "apisix" if header_name?(/\Ax-apisix-/) || server.include?("apisix")
      return "envoy" if header("x-envoy-upstream-service-time")
      return "aws-elb" if server.include?("awselb")
      return "google" if server.include?("google frontend") || server == "gws"

      nil
    end

    def detect_cdn
      return "cloudflare" if header("cf-ray") || @server.to_s.match?(/cloudflare/i)
      return "cloudfront" if header("x-amz-cf-id") || @via.to_s.match?(/cloudfront/i) ||
                             header("x-cache").to_s.match?(/cloudfront/i)
      return "fastly" if header("x-fastly-request-id") || header("x-served-by").to_s.match?(/fastly/i) ||
                          @via.to_s.match?(/fastly/i)
      return "akamai" if header_name?(/\Ax-akamai-/) || header("akamai-grn") ||
                          @server.to_s.match?(/akamai/i)
      return "azure-front-door" if header("x-azure-ref") || header("x-msedge-ref")
      return "google-cloud-cdn" if header_name?(/\Ax-goog-/) || @via.to_s.match?(/\bgoogle\b/i)
      return "bunny" if header_name?(/\Ax-bunny-/i) || @server.to_s.match?(/bunny/i)
      return "alibaba-cloud" if header("eagleid") || header("ali-swift-global-savetime")
      return "tencent-cloud" if header("x-nws-log-uuid") || @server.to_s.match?(/tencent/i)
      return "vercel" if header_name?(/\Ax-vercel-/i) || @server.to_s.match?(/vercel/i)
      return "netlify" if header("x-nf-request-id") || @server.to_s.match?(/netlify/i)
      return "cloudways" if header_name?(/\Ax-cloudways-/i)
      return "kinsta" if header_name?(/\Ax-kinsta-/i)
      return "wp-engine" if header("x-wp-engine") || @server.to_s.match?(/wp engine/i)
      return "fastly" if header("x-varnish") && header("x-cache")

      nil
    end

    def detect_waf
      return "ovhcloud" if @block_page&.vendor == "OVHcloud"
      return "cloudflare" if header("cf-ray") || header("cf-mitigated") || @server.to_s.match?(/cloudflare/i)
      return "sucuri" if header("x-sucuri-id") || bodies.match?(/Sucuri Website Firewall/i)
      return "imperva" if header("x-iinfo") || header("x-cdn").to_s.match?(/incapsula/i) ||
                          bodies.match?(/Incapsula/i)
      return "akamai" if header("akamai-grn") || bodies.match?(/Reference #\d+/i)
      return "aws-waf" if header("x-amzn-waf-action") ||
                          bodies.match?(/AWS WAF|request blocked by AWS/i)
      return "f5-big-ip" if header("x-wa-info") || bodies.match?(/The requested URL was rejected/i) ||
                            @probes.any? { |p| p.set_cookies.any? { |c| c.match?(/\ATS[0-9a-f]{8}=/i) } }
      return "modsecurity" if @server.to_s.match?(/modsecurity/i) || bodies.match?(/Not Acceptable/i)
      return "wordfence" if bodies.match?(/Wordfence/i)
      return "fortiweb" if bodies.match?(/FortiWeb/i) ||
                           @probes.any? { |p| p.set_cookies.any? { |c| c.match?(/FORTIWAFSID/i) } }
      return "barracuda" if @probes.any? { |p| p.set_cookies.any? { |c| c.match?(/barra_counter_session/i) } }
      return "unidentified edge control" if @access.blocked?
      return "rate limiter" if @access.state == :rate_limited

      nil
    end

    def detect_hosting
      return "OVHcloud" if header("x-ovh-webhosting-id")
      return "cPanel" if header_name?(/\Ax-cpanel-/i) || @server.to_s.match?(/cpanel/i)
      return "Plesk" if header("x-powered-by").to_s.match?(/PleskLin/i) || @server.to_s.match?(/plesk/i)
      return "WP Engine" if header("x-wp-engine") || @server.to_s.match?(/wp engine/i)
      return "Kinsta" if header_name?(/\Ax-kinsta-/i)
      return "Vercel" if header_name?(/\Ax-vercel-/i)
      return "Netlify" if header("x-nf-request-id")
      return "Render" if header_name?(/\Ax-render-/i)
      return "Fly.io" if header("fly-request-id")
      return "Heroku" if @server.to_s.match?(/heroku/i)
      return "Cloudways" if header_name?(/\Ax-cloudways-/i)
      return "Platform.sh" if header_name?(/\Ax-platformsh-/i)
      return "Acquia" if header_name?(/\Ax-acquia-/i)
      return "Pantheon" if header_name?(/\Ax-pantheon-/i)

      nil
    end

    # The SAPI decides exploit reliability, which is why it earns a written
    # rationale alongside the value. mod_php gives one request one process
    # with no recycle between victims; FPM forces an attacker to land both
    # requests on the same worker.
    def detect_sapi
      server = @server.to_s.downcase
      php    = php_detected?

      # A block page is answered by the edge, not the origin. Inferring FPM
      # from "openresty" here would turn an unknown into false precision.
      if !php && @access && !@access.open?
        return ["unknown",
                sapi_note("unobservable",
                          "the edge answered before the origin; the SAPI is not observable from this response")]
      end

      if server.include?("litespeed")
        ["litespeed", sapi_note("litespeed", "LiteSpeed SAPI — affected per the PHP advisory")]
      elsif server.include?("apache") && !cdn?
        ["mod_php (likely)",
         sapi_note("mod_php_likely",
                   "Apache server header with no CDN in front — the highest-risk setup per the PHP team")]
      elsif server.include?("apache")
        ["mod_php (possible)",
         sapi_note("mod_php_possible",
                   "Apache behind %{cdn}; the origin SAPI is unconfirmed from outside", cdn: cdn)]
      elsif server.include?("openresty")
        ["php-fpm (possible)",
         sapi_note("fpm_openresty",
                   "openresty is nginx-based and commonly proxies to PHP-FPM; worker affinity is unconfirmed")]
      elsif server.include?("nginx") || header("x-fastcgi-cache")
        ["php-fpm (likely)",
         sapi_note("fpm_likely",
                   "nginx/fastcgi fingerprint — FPM is affected but needs same-worker request pairing")]
      elsif server.include?("iis")
        ["php-cgi (possible)",
         sapi_note("cgi_iis",
                   "IIS front end with PHP markers — CGI/FastCGI SAPI, worker model unconfirmed")]
      elsif (server.include?("caddy") || server.include?("traefik") || server.include?("envoy")) && php
        ["php-fpm (possible)",
         sapi_note("fpm_front_end",
                   "%{edge} front end with PHP markers — usually proxies to FPM", edge: @edge)]
      else
        ["unknown", sapi_note("unknown", "no SAPI fingerprint exposed")]
      end
    end

    def sapi_note(key, default, **vars)
      I18n.t("data.environment.sapi.#{key}", default: default, **vars)
    end
  end
end
