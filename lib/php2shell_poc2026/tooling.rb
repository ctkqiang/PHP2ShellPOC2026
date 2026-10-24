# frozen_string_literal: true

require_relative "i18n"

module PHP2ShellPOC2026
  # The kit list, filtered to what is relevant to this finding. The old
  # catalogue printed every tool in every phase regardless of whether the
  # host was blocked, patched, WordPress or static; that is a wall of text,
  # not advice. Priority 3 = start here, 2 = worth running, 1 = full
  # catalogue only.
  #
  # Offensive entries are gated behind --authorized. A passive triage tool
  # should not hand a stranger a post-exploitation shopping list by default.
  module Tooling
    Entry = Struct.new(:phase, :tool, :purpose, :relevance, :techniques, :url,
                       :priority, :offensive, keyword_init: true) do
      def to_h
        {
          phase: phase, tool: tool, purpose: purpose, relevance: relevance,
          techniques: techniques, url: url, priority: priority, offensive: offensive
        }
      end
    end

    PHASES = [
      "Reconnaissance",
      "Scanning & enumeration",
      "Framework fingerprinting",
      "Vulnerability assessment",
      "Verification",
      "Exploitation (authorized)",
      "Post-exploitation (authorized)",
      "OPSEC & reporting"
    ].freeze

    def self.catalogue(verdict, environment, options)
      entries = core(verdict, environment, options)
      entries = entries.reject(&:offensive) unless options.authorized
      entries = entries.select { |entry| entry.priority >= 2 } unless options.toolchain_full
      entries.sort_by { |entry| [PHASES.index(entry.phase) || 99, -entry.priority, entry.tool] }
    end

    def self.core(verdict, environment, options)
      entries = [
        entry("Reconnaissance", "subfinder / Amass",
              t("data.tooling.subfinder.purpose",
                "Passive subdomain enumeration with source deduplication and resolution checks."),
              t("data.tooling.subfinder.relevance",
                "Side hosts, staging boxes and forgotten vhosts trail the flagship's patch level. The PHP2Shell fix " \
                "is only as current as the least-maintained subdomain you own."),
              %w[T1596], 2),
        entry("Reconnaissance", "crt.sh / certificate transparency",
              t("data.tooling.ct.purpose",
                "Search public certificate logs for hostnames and origin certificates."),
              t("data.tooling.ct.relevance",
                "CT logs routinely expose the real origin behind a CDN, plus sibling hosts that share the same " \
                "interpreter."),
              %w[T1596], environment.cdn? ? 3 : 2),
        entry("Reconnaissance", "Shodan / Censys / ZoomEye",
              t("data.tooling.shodan.purpose",
                "Internet-wide banner search: server headers, certificates and exposed panels from hosts nobody " \
                "remembered existed."),
              t("data.tooling.shodan.relevance",
                "Useful for corroborating the server/edge fingerprint and finding the origin when a CDN is in front."),
              %w[T1592 T1596], environment.cdn? ? 3 : 1),
        entry("Reconnaissance", "gau / waybackurls",
              t("data.tooling.gau.purpose",
                "Pull every URL public crawlers have recorded for the domain."),
              t("data.tooling.gau.relevance",
                "Retired .php endpoints often stay routed to live backends for years; each is an independent entry " \
                "point for a parser bug."),
              %w[T1593], 1),

        entry("Scanning & enumeration", "httpx",
              t("data.tooling.httpx.purpose",
                "Probe a host list and return only live endpoints with status, title and technology fingerprint."),
              t("data.tooling.httpx.relevance",
                "Separates serving hosts from dead DNS before spending scan budget — the difference between a " \
                "two-hour recon and a two-day one."),
              %w[T1595], 3),
        entry("Scanning & enumeration", "WhatWeb / Wappalyzer",
              t("data.tooling.whatweb.purpose",
                "Technology fingerprinting from responses: CMS, framework, server stack, version hints."),
              t("data.tooling.whatweb.relevance",
                "Corroborates the passive headers this tool reads. Disagreement usually means a CDN is masking the " \
                "origin stack."),
              %w[T1592], 3),
        entry("Scanning & enumeration", "curl",
              t("data.tooling.curl.purpose",
                "Minimal, scriptable HTTP with full control of method, headers and body."),
              t("data.tooling.curl.relevance",
                "A three-line GET is the most honest reproduction of what this scanner saw; use it to verify the " \
                "status from your own egress."),
              %w[T1595], 3),
        entry("Scanning & enumeration", "openssl s_client / dig",
              t("data.tooling.openssl.purpose",
                "Read the TLS certificate chain and DNS records directly."),
              t("data.tooling.openssl.relevance",
                "Certificate SANs, issuer and DNS history are passive origin-discovery signals; both are safe and " \
                "server-side only."),
              %w[T1592 T1596], 2),
        entry("Scanning & enumeration", "Nmap (+ NSE http-title/http-headers)",
              t("data.tooling.nmap.purpose",
                "Service and version detection across open ports, with HTTP enumeration scripts."),
              t("data.tooling.nmap.relevance",
                "PHP does not only live on 443. Exposed FPM sockets (9000), admin panels on odd ports and dev " \
                "servers bound to 0.0.0.0 are found by port scans, never by web crawlers."),
              %w[T1046], verdict.no_php? ? 3 : 1),
        entry("Scanning & enumeration", "ffuf / Feroxbuster",
              t("data.tooling.ffuf.purpose",
                "Directory and file discovery with recursion into matched folders."),
              t("data.tooling.ffuf.relevance",
                "Map .php entry points — login, cron, xmlrpc, upload handlers, forgotten test scripts. Only run " \
                "within an authorized scope and a rate the target can tolerate."),
              %w[T1595], verdict.unverified? ? 1 : 2),
        entry("Scanning & enumeration", "wafw00f",
              t("data.tooling.wafw00f.purpose",
                "Probe how the edge reacts to benign requests and identify the WAF vendor, or its absence."),
              t("data.tooling.wafw00f.relevance",
                "Tells you whether the detection notes in this report are already covered at the edge, and whether " \
                "origin exposure needs its own pass."),
              %w[T1595], environment.waf ? 3 : 1),

        entry("Framework fingerprinting", "WPScan",
              t("data.tooling.wpscan.purpose",
                "WordPress core, theme and plugin enumeration with known-vulnerability mapping."),
              t("data.tooling.wpscan.relevance",
                "WordPress is PHP by definition, and plugin/theme drift is where unpatched interpreters hide " \
                "longest."),
              %w[T1592 T1595], environment.frameworks.any? { |f| f.name == "WordPress" } ? 3 : 1),
        entry("Framework fingerprinting", "Droopescan",
              t("data.tooling.droopescan.purpose",
                "Drupal/Joomla/SilverStripe version and plugin enumeration."),
              t("data.tooling.droopescan.relevance",
                "Only relevant when one of those frameworks is detected; it turns the generic finding into a " \
                "concrete component inventory."),
              %w[T1592], environment.frameworks.any? { |f| %w[Drupal Joomla].include?(f.name) } ? 3 : 1),

        entry("Vulnerability assessment", "Nuclei (tech-detect + custom template)",
              t("data.tooling.nuclei.purpose",
                "Template-driven technology and exposure checks; write one template for the X-Powered-By floor."),
              t("data.tooling.nuclei.relevance",
                "A single template can flag every host below the fix level and inherit the check into continuous " \
                "monitoring."),
              %w[T1595], verdict.exposed? ? 3 : 2),
        entry("Vulnerability assessment", "SearchSploit / Exploit-DB",
              t("data.tooling.searchsploit.purpose",
                "Public exploit-code search, mirrored locally."),
              t("data.tooling.searchsploit.relevance",
                "Establishes whether a bug class has been commoditized — a statement about the adversary's skill " \
                "bar, not just your patch queue."),
              [], 1),
        entry("Vulnerability assessment", "Burp Suite / OWASP ZAP",
              t("data.tooling.burp.purpose",
                "Intercepting proxy for replay, mutation and byte-level request comparison."),
              t("data.tooling.burp.relevance",
                "Parser bugs live in malformed bodies and unusual header ordering — exactly the traffic blind " \
                "scanners drop."),
              %w[T1190], 2),

        entry("Verification", "Host-side version read",
              t("data.tooling.host_read.purpose",
                "Read php -v, the package manager, or a protected phpinfo page on the host."),
              t("data.tooling.host_read.relevance",
                "The only authoritative answer when the edge is blocking or the header is stripped. CLI and FPM " \
                "can read different php.ini files, so verify the web SAPI."),
              [], verdict.unverified? ? 3 : 1),
        entry("Verification", "Browser DevTools / curl from approved egress",
              t("data.tooling.egress.purpose",
                "Reproduce the request from a normal browser or an approved proxy to distinguish a scanner block " \
                "from an application response."),
              t("data.tooling.egress.relevance",
                "A 403 to a non-browser client is often bot management, not a patch. Confirm before drawing a " \
                "conclusion."),
              %w[T1595], verdict.access&.blocked? ? 3 : 1),

        entry("Exploitation (authorized)", "Metasploit exploit modules",
              t("data.tooling.metasploit.purpose",
                "Deliver a tested payload against a confirmed-vulnerable interpreter with handlers and sessions."),
              t("data.tooling.metasploit.relevance",
                "mod_php is close to one-shot; FPM forces both requests onto the same worker, so expect retries."),
              %w[T1190 T1059.004], 3, true),
        entry("Exploitation (authorized)", "Burp Repeater / Intruder",
              t("data.tooling.repeater.purpose",
                "Iterate crafted multipart bodies one mutation at a time."),
              t("data.tooling.repeater.relevance",
                "Exploit development against a parser needs line-level control of the raw request."),
              %w[T1190], 2, true),
        entry("Exploitation (authorized)", "pwntools",
              t("data.tooling.pwntools.purpose",
                "Scriptable protocol interaction with timing control."),
              t("data.tooling.pwntools.relevance",
                "The OOM variant is a race against worker memory; a harness beats clicking Replay."),
              %w[T1190], 1, true),

        entry("Post-exploitation (authorized)", "LinPEAS / GTFOBins",
              t("data.tooling.linpeas.purpose",
                "Privilege-escalation enumeration and living-off-the-land paths."),
              t("data.tooling.linpeas.relevance",
                "The bug buys www-data; escalation enumeration is the next step after a shell lands."),
              %w[T1082 T1083 T1059.004], 1, true),
        entry("Post-exploitation (authorized)", "chisel / ligolo-ng",
              t("data.tooling.chisel.purpose",
                "Tunnel and pivot tooling for segmented web tiers."),
              t("data.tooling.chisel.relevance",
                "Web tiers rarely have useful egress; a stable channel is a prerequisite for post-exploitation."),
              %w[T1090 T1105], 1, true),

        entry("OPSEC & reporting", "mitmproxy / Burp",
              t("data.tooling.mitmproxy.purpose",
                "Inspect your own scanner traffic and header order."),
              t("data.tooling.mitmproxy.relevance",
                "Half of 'the WAF blocked us' is our own tool sending a signature-like User-Agent or abnormal " \
                "header order. Inspect yourself before blaming the edge."),
              [], 1),
        entry("OPSEC & reporting", "Faraday / Dradis / Serpico",
              t("data.tooling.faraday.purpose",
                "Findings management, evidence and report assembly."),
              t("data.tooling.faraday.relevance",
                "Structured output the blue team can import is the difference between a finding and a fix."),
              [], 1)
      ]

      if environment.cdn?
        entries << entry(
          "Reconnaissance", "Origin discovery (crt.sh / historical DNS / Censys)",
          t("data.tooling.origin.purpose", "Reconstruct the real origin behind %{cdn}.", cdn: environment.cdn),
          t("data.tooling.origin.relevance",
            "Prioritised because this host is fronted: if the origin answers directly, every edge rule and rate " \
            "limit is decorative."),
          %w[T1596], 3
        )
      end

      if verdict.exposed?
        entries << entry(
          "Vulnerability assessment", "Nuclei PHP2Shell template",
          t("data.tooling.php2shell.purpose",
            "Check the interpreter version and the upload-progress surface at scale."),
          t("data.tooling.php2shell.relevance",
            "Once a host is confirmed exposed, the next useful step is finding every sibling with the same " \
            "version — not re-confirming this one."),
          %w[T1595], 3
        )
      end

      entries
    end

    def self.entry(phase, tool, purpose, relevance, techniques, priority, offensive = false)
      Entry.new(phase: phase, tool: tool, purpose: purpose, relevance: relevance,
                techniques: techniques, url: nil, priority: priority, offensive: offensive)
    end

    def self.t(key, default, **vars)
      I18n.t(key, default: default, **vars)
    end
    private_class_method :t
  end
end
