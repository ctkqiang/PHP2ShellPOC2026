# frozen_string_literal: true

require_relative "i18n"

module PHP2ShellPOC2026
  # Purple-team output: detection opportunities keyed to what was actually
  # observed on this host, not a generic hardening checklist. Layers run
  # outermost-first (WAF → network → logs → runtime → EDR) because that is
  # the order traffic meets them.
  module Detections
    Layer = Struct.new(:layer, :control, :detail, keyword_init: true) do
      def to_h
        { layer: layer, control: control, detail: detail }
      end
    end

    def self.for(verdict, environment)
      layers = []
      layers.concat(exposure_layers) if verdict.exposed?
      layers << origin_layer(environment) if environment.cdn?
      layers.concat(edge_layers(verdict, environment)) if verdict.unverified?
      layers << soft_404_layer if verdict.access&.state == :soft_404
      layers << rate_limit_layer if verdict.access&.state == :rate_limited
      layers << no_php_layer if verdict.no_php?
      layers << config_layer
      layers
    end

    def self.exposure_layers
      [
        Layer.new(
          layer: layer("waf", "WAF"),
          control: t("data.detection.exposure.upload.control",
                     "Block the upload-progress arm (CVE-2026-109619)"),
          detail: t("data.detection.exposure.upload.detail",
                    "AWS WAF: custom rule matching POST where body contains PHP_SESSION_UPLOAD_PROGRESS and PHPSESSID " \
                    "(body or cookie); the AWS WAF PHP Managed Rule Group v2.3+ covers this. " \
                    "ModSecurity: inspect multipart bodies for PHP_SESSION_UPLOAD_PROGRESS outside expected upload forms.")
        ),
        Layer.new(
          layer: layer("waf_proxy", "WAF/Proxy"),
          control: t("data.detection.exposure.oom.control",
                     "Shrink the OOM trigger surface (CVE-2026-109618)"),
          detail: t("data.detection.exposure.oom.detail",
                    "Enforce body-size limits on *decoded* requests (AWS WAF SizeRestrictions_BODY, 8 KB, if uploads " \
                    "aren't needed), multipart part count, field count, header count and nesting depth — including " \
                    "requests without a usable Content-Length.")
        ),
        Layer.new(
          layer: layer("php_logs", "PHP logs"),
          control: t("data.detection.exposure.logs.control",
                     "Hunt memory-exhaustion during request startup"),
          detail: t("data.detection.exposure.logs.detail",
                    'Grep FPM/Apache error logs for "Allowed memory size of ... exhausted", "Cannot allocate memory" ' \
                    "and fatal errors *before* the script name appears — that ordering is the CVE-2026-109618 signature.")
        ),
        Layer.new(
          layer: layer("web_tier", "Web tier"),
          control: t("data.detection.exposure.workers.control", "Worker health anomalies"),
          detail: t("data.detection.exposure.workers.detail",
                    "mod_php: Apache child segfaults/restarts, core dumps. FPM: abnormal worker exits and rapid " \
                    "respawn storms. Exploitation can also succeed without any crash — absence of segfaults is not clean.")
        ),
        Layer.new(
          layer: layer("edr", "EDR"),
          control: t("data.detection.exposure.edr.control", "Shell spawned by web worker UID"),
          detail: t("data.detection.exposure.edr.detail",
                    "Alert on /bin/sh, bash, curl, wget or python spawned by www-data/apache immediately after an " \
                    "inbound HTTP request; this is the post-exploitation pivot regardless of which CVE landed.")
        ),
        Layer.new(
          layer: layer("application", "Application"),
          control: t("data.detection.exposure.disclosure.control", "Memory-disclosure response anomalies"),
          detail: t("data.detection.exposure.disclosure.detail",
                    "Endpoints returning abnormally large or non-HTML bodies, or session cookies reflecting " \
                    "unexpected memory contents — the info-leak half of the bug class.")
        )
      ]
    end

    # A CDN in front usually means the origin is not where defenders think
    # it is — edge rules protect the front door only.
    def self.origin_layer(environment)
      Layer.new(
        layer: layer("network", "Network"),
        control: t("data.detection.origin.control", "Origin reachability audit"),
        detail: t("data.detection.origin.detail",
                  "CDN (%{cdn}) fronts the app, but direct-to-origin requests bypass its rules. " \
                  "Confirm origin ports accept traffic only from the CDN range.", cdn: environment.cdn)
      )
    end

    # The most important lesson of a 403: it is an observation about the
    # edge, not a clean bill of health for the interpreter.
    def self.edge_layers(verdict, environment)
      layers = []
      if verdict.access&.blocked?
        layers << Layer.new(
          layer: layer("edge", "Edge"),
          control: t("data.detection.edge.blocked.control",
                     "Uniform denial — confirm intent and do not treat it as a patch"),
          detail: t("data.detection.edge.blocked.detail",
                    "Every probe, including a random control path, returned the same denial " \
                    "(%{statuses}). Verify whether this is geo/IP blocking, " \
                    "bot management or a WAF rule. Log canary-path requests as reconnaissance, and ensure the origin " \
                    "is not reachable directly outside the edge.",
                    statuses: verdict.access.details[:statuses].join("/"))
        )
      elsif verdict.access&.restricted?
        layers << Layer.new(
          layer: layer("edge", "Edge"),
          control: t("data.detection.edge.restricted.control", "Path-level access control"),
          detail: t("data.detection.edge.restricted.detail",
                    "The root path was denied while a random control path resolved differently. Check whether the " \
                    "restriction is intentional and whether alternate vhosts or paths expose the same interpreter.")
        )
      elsif verdict.access&.state == :auth_wall
        layers << Layer.new(
          layer: layer("application", "Application"),
          control: t("data.detection.edge.auth.control", "Authentication wall"),
          detail: t("data.detection.edge.auth.detail",
                    "The surface redirects to a login. Version evidence from headers may still leak; host-side " \
                    "verification is the reliable path unless authenticated testing is authorized.")
        )
      end

      layers << Layer.new(
        layer: layer("recon_detection", "Recon detection"),
        control: t("data.detection.edge.canary.control", "Random canary-path requests"),
        detail: t("data.detection.edge.canary.detail",
                  "This scan requests a random nonexistent path to distinguish a blanket denial from a real 404. " \
                  "Alert on bursts of random-path requests from one source; they are a reliable scanner signature.")
      )
      layers
    end

    def self.soft_404_layer
      Layer.new(
        layer: layer("edge", "Edge"),
        control: t("data.detection.soft_404.control", "Catch-all/soft-404 routing"),
        detail: t("data.detection.soft_404.detail",
                  "The origin returns 200 for nonexistent paths, so path status codes and directory brute-force " \
                  "results are unreliable. Prefer header, cookie and phpinfo evidence; validate findings with a " \
                  "body/content differential.")
      )
    end

    def self.rate_limit_layer
      Layer.new(
        layer: layer("edge", "Edge"),
        control: t("data.detection.rate_limit.control", "Rate limiting observed (HTTP 429)"),
        detail: t("data.detection.rate_limit.detail",
                  "The origin is throttling. Respect Retry-After, raise the scanner delay, and do not interpret a " \
                  "429 as absence of the application.")
      )
    end

    def self.no_php_layer
      Layer.new(
        layer: layer("verification", "Verification"),
        control: t("data.detection.no_php.control", "No PHP on the tested routes"),
        detail: t("data.detection.no_php.detail",
                  "No PHP markers were observed and the control path behaved normally. This covers only the paths " \
                  "that were tested: check other vhosts, ports, subdomains and application routes before concluding " \
                  "the estate is PHP-free.")
      )
    end

    # Unconditional because it applies to hosts we could not fingerprint too:
    # "unknown version" is a reason to verify the hardening, not to skip it.
    def self.config_layer
      Layer.new(
        layer: layer("config_audit", "Config audit"),
        control: t("data.detection.config.control", "Verify effective PHP hardening (host-side)"),
        detail: t("data.detection.config.detail",
                  "session.upload_progress.enabled=Off, memory_limit=-1 (php_admin_value, not overridable), " \
                  "fatal_error_backtraces=0 on 8.5, low post_max_size. Verify from a live web request (phpinfo), " \
                  "not the CLI — and restart every worker after changes.")
      )
    end

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end

    def self.layer(key, default)
      I18n.t("data.detection.layer.#{key}", default: default)
    end
    private_class_method :t, :layer
  end
end
