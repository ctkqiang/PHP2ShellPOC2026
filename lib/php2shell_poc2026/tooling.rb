# frozen_string_literal: true

module PHP2ShellPOC2026
  # The kit list — the tools a team actually brings to an engagement against
  # a PHP-facing estate, ordered the way an engagement runs rather than
  # alphabetically. Purposes and relevance lines stay long on purpose: this
  # doubles as onboarding material for operators who know the phase names by
  # heart but not why a given tool earned its slot in that phase.
  #
  # Nothing here exploits anything. The catalogue is scoping and planning
  # context printed next to a passive finding, not a set of instructions.
  module Tooling
    Entry = Struct.new(:phase, :tool, :purpose, :relevance, :techniques, keyword_init: true)

    # Order matters — Report groups by first appearance, so this array is
    # the order the catalogue prints in.
    def self.catalogue(_verdict, environment)
      entries = core
      entries << origin_discovery(environment) if environment.cdn?
      entries
    end

    def self.core
      [
        # -- Reconnaissance -------------------------------------------------
        entry(
          "Reconnaissance", "Amass / subfinder",
          "Passive subdomain enumeration at scale — every name anyone has ever published for the domain, " \
          "with sources deduplicated and resolution checked.",
          "Side hosts, staging boxes and forgotten vhosts trail the flagship site's patch level almost by " \
          "definition. The PHP2Shell fix is only as current as the least-maintained subdomain you own.",
          %w[T1596]
        ),
        entry(
          "Reconnaissance", "theHarvester",
          "Harvests emails, employee names and related identity data from public sources: breach dumps, " \
          "search engines, collaboration sites.",
          "Feeds pretexting for vishing and on-site social engineering. Identity operations run before any " \
          "packet touches the target's infrastructure.",
          %w[T1589]
        ),
        entry(
          "Reconnaissance", "Shodan / Censys / ZoomEye",
          "Internet-wide banner search across ports and protocols — historical certificates, exposed panels, " \
          "server headers from hosts nobody remembered existed.",
          "TLS certificate transparency and historical DNS routinely leak the real origin behind a CDN. Worth " \
          "knowing, because every edge rule evaporates the moment someone talks to the origin directly.",
          %w[T1592 T1596]
        ),
        entry(
          "Reconnaissance", "gau / waybackurls",
          "Pulls every URL a crawler or search engine has ever recorded for a domain, from public archives.",
          "Retired .php endpoints often stay routed to live backends for years. Each is an independent entry " \
          "point — and for a parser bug that fires before routing, path allowlists buy nothing.",
          %w[T1593]
        ),
        entry(
          "Reconnaissance", "wafw00f",
          "Probes how a target reacts to benign and borderline requests to identify the WAF vendor, or the " \
          "absence of one.",
          "Tells you whether the detection notes in this report are already covered at the edge, and whether " \
          "origin exposure needs its own testing pass.",
          %w[T1595]
        ),

        # -- Scanning & enumeration ----------------------------------------
        entry(
          "Scanning & enumeration", "httpx",
          "Takes host and URL lists and returns only what is live, with status codes, title and technology " \
          "fingerprint attached.",
          "Separates serving hosts from dead DNS before anyone burns scan budget — the difference between a " \
          "two-hour recon and a two-day one.",
          %w[T1595]
        ),
        entry(
          "Scanning & enumeration", "Nmap (+ NSE scripts)",
          "Service and version detection across open ports, with scriptable checks for HTTP enumeration and " \
          "header inspection.",
          "PHP does not only live on 443. Exposed FPM sockets (9000), admin panels on odd ports and dev " \
          "servers bound to 0.0.0.0 are found by port scans, never by web crawlers.",
          %w[T1046]
        ),
        entry(
          "Scanning & enumeration", "RustScan",
          "Fast parallel port sweep designed to feed its output straight into Nmap for detailed service checks.",
          "Same job as Nmap run at a pace that fits inside a short red-team window when the clock is the " \
          "binding constraint.",
          %w[T1046]
        ),
        entry(
          "Scanning & enumeration", "ffuf / Feroxbuster",
          "Directory and file brute-forcing against discovered hosts, with recursion into matched folders.",
          "Map every .php entry point — login, cron, xmlrpc, upload handlers, forgotten test scripts. For a " \
          "request-parsing bug any of them is a valid front door, so surface area is the target.",
          %w[T1595]
        ),
        entry(
          "Scanning & enumeration", "WhatWeb / Wappalyzer",
          "Technology fingerprinting from responses: CMS, framework, server stack, version hints.",
          "Corroborates the passive headers this tool reads. Disagreement between the two usually means a CDN " \
          "is masking the origin stack.",
          %w[T1592]
        ),
        entry(
          "Scanning & enumeration", "WPScan",
          "WordPress-specific enumeration: core version, active theme, plugins and their known vulnerabilities.",
          "WordPress is PHP by definition, and plugin/theme version drift is where unpatched interpreters hide " \
          "longest — this engagement's own artifacts came from exactly this tool.",
          %w[T1592 T1595]
        ),

        # -- Vulnerability assessment --------------------------------------
        entry(
          "Vulnerability assessment", "Nuclei (projectdiscovery)",
          "Template-driven vulnerability scanning — a large community template library plus first-party " \
          "templates you write yourself.",
          "Write one template that flags X-Powered-By below the fix floor and every future host inherits the " \
          "check; the finding in this report is one template away from continuous monitoring.",
          %w[T1595]
        ),
        entry(
          "Vulnerability assessment", "SearchSploit / Exploit-DB",
          "Public exploit-code search, mirrored locally by searchsploit for offline lookup.",
          "Establishes whether a bug class has been commoditized — which is a statement about how " \
          "sophisticated your adversary needs to be, not just about your patch queue.",
          []
        ),
        entry(
          "Vulnerability assessment", "Metasploit Framework",
          "Auxiliary scanners, exploit modules and payload staging under one framework with a shared data model.",
          "The reference implementation for post-exploitation tradecraft — and the fastest way to learn whether " \
          "public modules already cover a class before writing anything yourself.",
          %w[T1190]
        ),
        entry(
          "Vulnerability assessment", "Burp Suite / OWASP ZAP",
          "Intercepting proxy for manual request surgery: replay, mutate, compare, single-step every byte.",
          "Parser bugs live in malformed multipart bodies and unusual header ordering — exactly the traffic " \
          "blind scanners drop on the floor.",
          %w[T1190]
        ),
        entry(
          "Vulnerability assessment", "curl",
          "Minimal, scriptable HTTP with no ceremony — full control of method, headers and body in a one-liner.",
          "A three-line POST is often the most honest reproduction of a request-parsing vulnerability: no proxy " \
          "rewriting the request, no framework normalising it.",
          %w[T1190]
        ),
        entry(
          "Vulnerability assessment", "php2shell-poc2026 (this tool)",
          "Passive exposure triage: interpreter version, deployment fingerprint, risk weighting, ATT&CK mapping " \
          "and detection opportunities — ordinary GET requests only.",
          "The scoping step that decides which of the tools in this catalogue are worth running against a host, " \
          "and in what order.",
          []
        ),

        # -- Exploitation (authorized) --------------------------------------
        entry(
          "Exploitation (authorized)", "Metasploit exploit modules",
          "Deliver a tested payload against a confirmed-vulnerable interpreter, with handlers and session " \
          "management included.",
          "mod_php's one-process-per-request model makes first-shot success likely; FPM forces both requests " \
          "onto the same worker, so expect retries and session pinning.",
          %w[T1190 T1059.004]
        ),
        entry(
          "Exploitation (authorized)", "Burp Repeater / Intruder",
          "Iterate crafted bodies — PHP_SESSION_UPLOAD_PROGRESS variants, oversized multiparts, malformed " \
          "boundary framing — one mutation at a time.",
          "Exploit development against a parser needs line-level control of the raw request. Proxies give it; " \
          "point-and-shoot scanners do not.",
          %w[T1190]
        ),
        entry(
          "Exploitation (authorized)", "pwntools",
          "Scriptable protocol interaction with timing control, for exploits that are a sequence of coordinated " \
          "requests rather than a single payload.",
          "The OOM variant is a race against worker memory — when the exploit is timing-sensitive, a scripting " \
          "harness beats clicking Replay and hoping.",
          %w[T1190]
        ),

        # -- Post-exploitation ----------------------------------------------
        entry(
          "Post-exploitation", "LinPEAS / WinPEAS",
          "Privilege-escalation enumeration across the host: permissions, misconfigs, credentials, services.",
          "The bug buys you www-data, and www-data is a starting point, not a win. Escalation enumeration is " \
          "the first thing that happens after a shell lands.",
          %w[T1082 T1083]
        ),
        entry(
          "Post-exploitation", "GTFOBins",
          "Catalogue of living-off-the-land paths — how common binaries become shells, file readers or " \
          " privilege escalators.",
          "Once a shell exists most escalation paths need nothing you can download — useful when egress is " \
          "monitored and implanting tooling is the riskier move.",
          %w[T1059.004]
        ),
        entry(
          "Post-exploitation", "Impacket",
          "Windows and Active Directory interaction from a Linux foothold: psexec, wmiexec, secretsdump, " \
          "Kerberos attacks.",
          "The standard jump from a compromised web tier into the domain — web hosts usually have a service " \
          "account nobody rotated.",
          %w[T1021 T1570]
        ),
        entry(
          "Post-exploitation", "NetExec (formerly CrackMapExec)",
          "Spray, enumerate and pivot across SMB/WinRM estates with a single credential or hash.",
          "One credential, many hosts — lateral movement is where most engagements actually spend their clock.",
          %w[T1021 T1110]
        ),
        entry(
          "Post-exploitation", "chisel / ligolo-ng",
          "Tunnel and pivot tooling — reverse SOCKS over HTTP, or an agent that makes the target dial home " \
          "into your network.",
          "Web tiers sit in segmented subnets with boring egress. Without a stable channel, post-exploitation " \
          "is not possible at all.",
          %w[T1090 T1105]
        ),

        # -- Command & control ----------------------------------------------
        entry(
          "Command & control", "Cobalt Strike",
          "Commercial C2 with malleable profiles that reshape traffic at the byte level to imitate normal " \
          "applications.",
          "HTTPS C2 has to look like the app's own traffic, and profile discipline is what keeps TLS anomaly " \
          "alerting asleep through the operation.",
          %w[T1071.001 T1090]
        ),
        entry(
          "Command & control", "Sliver / Mythic / Havoc",
          "Open-source C2 frameworks with comparable tradecraft: extensible agents, profile-like traffic " \
          "shaping, modular tooling.",
          "Equivalent capability without procurement friction. Same requirement applies: egress must blend with " \
          "the web tier's normal patterns.",
          %w[T1071.001 T1090]
        ),
        entry(
          "Command & control", "Metasploit Meterpreter",
          "Staged payload delivery over an existing channel, with a session abstraction shared across exploits.",
          "Useful for validation engagements where standing up a full C2 stack would be overkill for the " \
          "questions being asked.",
          %w[T1059.004 T1105]
        ),

        # -- Persistence & collection ----------------------------------------
        entry(
          "Persistence & collection", "Webshell drop (T1505.003)",
          "A single writable .php file inside the web root, surviving credential rotation, deploys that do " \
          "not clean the tree, and user-password changes.",
          "This is the bug class's headline outcome: one parser exploit converts into durable access. It is " \
          "also why the EDR detection in this report keys on shells spawned by the web worker UID.",
          %w[T1505.003]
        ),
        entry(
          "Persistence & collection", "cron / systemd timers",
          "Scheduled re-entry: jobs that re-establish access on an interval independent of any shell.",
          "Cheap persistence that survives shell loss and frequently sits outside everyone's EDR scope — " \
          "check crontabs before declaring an incident contained.",
          %w[T1053.003]
        ),
        entry(
          "Persistence & collection", "rclone / rsync",
          "Bulk data movement out with throttling, filtering and resumable transfers.",
          "The memory-disclosure variant leaks env material — keys, tokens, session data — without needing a " \
          "shell, so collection can begin during the probing phase itself.",
          %w[T1567 T1005]
        ),
        entry(
          "Persistence & collection", "CyberChef",
          "Decode, decompress, re-encode and carve collected blobs in a visual pipeline you can replay.",
          "Session material and memory dumps rarely come out base64-clean; half of triage is transformation, " \
          "not analysis.",
          %w[T1140]
        ),

        # -- OPSEC & reporting ------------------------------------------------
        entry(
          "OPSEC & reporting", "proxychains / redirector mesh",
          "Force scanner and implant egress through infrastructure you own — VPS hops, VPN, domain-fronted " \
          "endpoints you can burn on short notice.",
          "Your scanner's source IP ends up in their WAF logs regardless of tooling; the only choice is whether " \
          "it is an address you can afford to lose.",
          %w[T1090]
        ),
        entry(
          "OPSEC & reporting", "mitmproxy",
          "Intercept, inspect and replay your own tooling's traffic from the terminal.",
          "Half of \"the WAF blocked us\" turns out to be our own tool retrying with a signature-like " \
          "User-Agent or an abnormal header order. Inspect yourself before blaming the edge.",
          []
        ),
        entry(
          "OPSEC & reporting", "Faraday / Serpico / Dradis",
          "Findings management and report assembly: structured evidence, dedup, reusable narrative templates.",
          "Red-team output the blue team can import without retyping is the difference between a finding and " \
          "a fix — reporting is a deliverable, not an afterthought.",
          []
        )
      ]
    end

    # A fronted host changes the priority order, so origin discovery earns its
    # own entry rather than being buried inside a generic Shodan line.
    def self.origin_discovery(environment)
      entry(
        "Reconnaissance", "Origin discovery (censys / crt.sh / historical DNS)",
        "Reconstruct the real origin behind #{environment.cdn}: certificate transparency logs, historical " \
        "DNS records, mail-header IPs, and TLS certificate reuse across hosts.",
        "Prioritised here because this host sits behind #{environment.cdn} — if the origin answers from a " \
        "direct IP, every WAF rule and rate limit in front of it is decorative.",
        %w[T1596]
      )
    end

    def self.entry(phase, tool, purpose, relevance, techniques)
      Entry.new(phase: phase, tool: tool, purpose: purpose, relevance: relevance, techniques: techniques)
    end
  end
end
