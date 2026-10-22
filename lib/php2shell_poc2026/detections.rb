# frozen_string_literal: true

module PHP2ShellPOC2026
  # Purple-team output: detection opportunities keyed to what was actually
  # observed on this host, not a generic hardening checklist. Layers run
  # outermost-first (WAF → network → logs → runtime → EDR) because that is
  # the order traffic meets them, and each detail names concrete rules,
  # greps or signals — a detection engineer should be able to act on a line
  # without opening this tool's source.
  module Detections
    Layer = Struct.new(:layer, :control, :detail, keyword_init: true)

    def self.for(verdict, environment)
      layers = []
      layers.concat(exposure_layers) if verdict.exposed?
      layers << origin_layer(environment) if environment.cdn?
      layers << config_layer
      layers
    end

    def self.exposure_layers
      [
        Layer.new(
          layer: "WAF", control: "Block the upload-progress arm (CVE-2026-109619)",
          detail: "AWS WAF: custom rule matching POST where body contains PHP_SESSION_UPLOAD_PROGRESS and PHPSESSID " \
                  "(body or cookie); the AWS WAF PHP Managed Rule Group v2.3+ covers this. " \
                  "ModSecurity: inspect multipart bodies for PHP_SESSION_UPLOAD_PROGRESS outside expected upload forms."
        ),
        Layer.new(
          layer: "WAF/Proxy", control: "Shrink the OOM trigger surface (CVE-2026-109618)",
          detail: "Enforce body-size limits on *decoded* requests (AWS WAF SizeRestrictions_BODY, 8 KB, if uploads " \
                  "aren't needed), multipart part count, field count, header count and nesting depth — including " \
                  "requests without a usable Content-Length."
        ),
        Layer.new(
          layer: "PHP logs", control: "Hunt memory-exhaustion during request startup",
          detail: 'Grep FPM/Apache error logs for "Allowed memory size of ... exhausted", "Cannot allocate memory" ' \
                  "and fatal errors *before* the script name appears — that ordering is the CVE-2026-109618 signature."
        ),
        Layer.new(
          layer: "Web tier", control: "Worker health anomalies",
          detail: "mod_php: Apache child segfaults/restarts, core dumps. FPM: abnormal worker exits and rapid " \
                  "respawn storms. Exploitation can also succeed without any crash — absence of segfaults is not clean."
        ),
        Layer.new(
          layer: "EDR", control: "Shell spawned by web worker UID",
          detail: "Alert on /bin/sh, bash, curl, wget or python spawned by www-data/apache immediately after an " \
                  "inbound HTTP request; this is the post-exploitation pivot regardless of which CVE landed."
        ),
        Layer.new(
          layer: "Application", control: "Memory-disclosure response anomalies",
          detail: "Endpoints returning abnormally large or non-HTML bodies, or session cookies reflecting " \
                  "unexpected memory contents — the info-leak half of the bug class."
        )
      ]
    end

    # A CDN in front usually means the origin is not where defenders think
    # it is — edge rules protect the front door only, so the first question
    # is always whether the back door is nailed shut.
    def self.origin_layer(environment)
      Layer.new(
        layer: "Network", control: "Origin reachability audit",
        detail: "CDN (#{environment.cdn}) fronts the app, but direct-to-origin requests bypass its rules. " \
                "Confirm origin ports accept traffic only from the CDN range."
      )
    end

    # Unconditional because it applies to hosts we could not fingerprint too:
    # "unknown version" is a reason to verify the hardening, not to skip it.
    def self.config_layer
      Layer.new(
        layer: "Config audit", control: "Verify effective PHP hardening (host-side)",
        detail: "session.upload_progress.enabled=Off, memory_limit=-1 (php_admin_value, not overridable), " \
                "fatal_error_backtraces=0 on 8.5, low post_max_size. Verify from a live web request (phpinfo), " \
                "not the CLI — and restart every worker after changes."
      )
    end
  end
end
