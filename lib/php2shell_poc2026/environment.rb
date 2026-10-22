# frozen_string_literal: true

module PHP2ShellPOC2026
  # What sits in front of PHP shapes both exploit reliability and which
  # controls can realistically stop it: mod_php makes an exploit one-shot,
  # FPM makes it a coin flip on worker affinity, a WAF decides whether the
  # blue-team notes in this report are already covered or aspirational.
  #
  # Everything here is inferred from response headers alone. Active
  # fingerprinting of someone else's edge is a conversation with their SOC,
  # not with their application, and this tool has no business starting it.
  class Environment
    attr_reader :server, :cdn, :waf, :sapi, :sapi_rationale

    def initialize(root_probe)
      headers = (root_probe && root_probe.headers) || {}
      @server = headers["server"]
      @cdn    = detect_cdn(headers)
      @waf    = detect_waf(headers)
      @sapi, @sapi_rationale = detect_sapi(headers)
    end

    def cdn?
      !cdn.nil?
    end

    def to_h
      { server: server, cdn: cdn, waf: waf, sapi: sapi, sapi_rationale: sapi_rationale }
    end

    private

    # CDN headers are vendor tells rather than proof of anything, but the
    # tell is the point: a fronted origin can almost always be found through
    # certificate transparency or old DNS, and finding it skips every edge
    # control in a single step.
    def detect_cdn(headers)
      return "cloudfront" if headers["x-amz-cf-id"] || headers["via"].to_s.match?(/cloudfront/i)
      return "cloudflare" if headers["cf-ray"]
      return "fastly"     if headers["x-served-by"].to_s.match?(/fastly/i) || headers["x-fastly-request-id"]
      return "akamai"     if headers.keys.any? { |k| k.match?(/\Ax-akamai/i) }

      nil
    end

    def detect_waf(headers)
      return "cloudflare" if headers["cf-ray"]
      return "sucuri"     if headers["x-sucuri-id"]
      return "incapsula"  if headers["x-iinfo"] || headers["x-cdn"]

      nil
    end

    # The SAPI decides exploit reliability, which is why it earns a written
    # rationale alongside the value: mod_php gives one request one process
    # with no recycle between victims, FPM forces an attacker to land both
    # requests on the same worker. Downstream risk scoring reads `sapi`,
    # a human reading the report reads the rationale.
    def detect_sapi(headers)
      srv = headers["server"].to_s

      if srv.match?(/litespeed/i)
        ["litespeed", "LiteSpeed SAPI — affected per PHP advisory"]
      elsif srv.match?(/apache/i) && !cdn
        ["mod_php (likely)", "Apache server header with no CDN in front — the highest-risk setup per the PHP team"]
      elsif srv.match?(/apache/i)
        ["mod_php (possible)", "Apache behind #{cdn}; origin SAPI unconfirmed from outside"]
      elsif srv.match?(/nginx/i) || headers["x-fastcgi-cache"]
        ["php-fpm (likely)", "nginx/fastcgi fingerprint — FPM is affected but needs same-worker request pairing"]
      else
        ["unknown", "no SAPI fingerprint exposed"]
      end
    end
  end
end
