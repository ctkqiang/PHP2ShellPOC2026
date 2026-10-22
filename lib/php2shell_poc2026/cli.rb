# frozen_string_literal: true

require "optparse"

module PHP2ShellPOC2026
  # Option parsing and exit codes — the only file that talks to the outside
  # world on behalf of a human. Scan orchestration lives in Scanner and
  # presentation in Report; this class exists so the boundary between "what
  # the user asked for" and "what the tool does" stays visible.
  class CLI
    EXIT_OK    = 0
    EXIT_ERROR = 1
    EXIT_VULN  = 2

    def initialize(argv)
      @argv    = argv
      @options = { deep: false, timeout: 10, verify_tls: true, json: false,
                   redteam: false, toolchain: false, verbose: false }
    end

    def run
      parse_options!

      if @argv.empty?
        warn "php2shell-poc2026: at least one URL is required (see --help)"
        return EXIT_ERROR
      end

      scanner = Scanner.new(
        timeout:    @options[:timeout],
        verify_tls: @options[:verify_tls],
        deep:       @options[:deep],
        verbose:    @options[:verbose]
      )

      results = scan_all(scanner)
      return EXIT_ERROR if results.empty?

      if @options[:json]
        puts Report.json(results)
      else
        Report::Text.new(
          results,
          redteam:   @options[:redteam],
          toolchain: @options[:toolchain],
          verbose:   @options[:verbose]
        ).render
      end

      results.values.any? { |r| r.verdict.exposed? } ? EXIT_VULN : EXIT_OK
    rescue OptionParser::ParseError => e
      warn "php2shell-poc2026: #{e.message}"
      EXIT_ERROR
    end

    private

    # A malformed target in the middle of a list should not take down the
    # run — drop it with a warning and report on whatever parsed. Operators
    # pasting mixed output from other tools routinely get one bad line in.
    def scan_all(scanner)
      results = {}
      @argv.each do |target|
        results[target] = scanner.scan(target)
      rescue URI::InvalidURIError => e
        warn "  ! skipping #{target}: #{e.message}"
      end
      results
    end

    def parse_options!
      OptionParser.new do |o|
        o.banner = "Usage: php2shell-poc2026 [options] URL [URL ...]"

        o.on("-d", "--deep", "Also probe /index.php and common phpinfo paths") { @options[:deep] = true }
        o.on("-t", "--timeout SECS", Integer, "Per-request timeout (default: 10)") { |v| @options[:timeout] = v }
        o.on("-k", "--insecure", "Skip TLS certificate verification") { @options[:verify_tls] = false }
        o.on("-r", "--redteam", "Include red team attacker-perspective notes") { @options[:redteam] = true }
        o.on("-c", "--toolchain", "Include the standard red team toolchain catalogue") { @options[:toolchain] = true }
        o.on("-v", "--verbose", "Trace every request and response while scanning") { @options[:verbose] = true }
        o.on("-j", "--json", "Emit the full JSON report (always complete, flags or not)") { @options[:json] = true }
        o.on("-V", "--version", "Print version and exit") do
          puts "php2shell-poc2026 #{VERSION}"
          exit EXIT_OK
        end
        o.on("-h", "--help", "Show this help") { puts o; exit EXIT_OK }
      end.parse!(@argv)
    end
  end
end
