# frozen_string_literal: true

require "cgi"
require "uri"

module PHP2ShellPOC2026
  # Passive discovery of real .php paths from robots.txt and sitemap.xml.
  # This is the polite alternative to directory brute-forcing: the site
  # publishes the paths itself, and the scanner only asks for a handful of
  # them.
  module Discovery
    LOC        = /<loc[^>]*>\s*(.*?)\s*<\/loc>/im
    SITEMAP    = /^\s*Sitemap:\s*(\S+)/i
    DISALLOW   = /^\s*Disallow:\s*(\S*)/i

    # Paths that change state or are likely to log the user out. A passive
    # scanner has no business touching them, even with GET.
    UNSAFE = /(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|cart|checkout|payment|admin-ajax)/i

    module_function

    def parse_robots(body, base_uri)
      sitemaps = []
      disallowed = []
      body.to_s.each_line do |line|
        if (match = line.match(SITEMAP))
          uri = absolute(match[1], base_uri)
          sitemaps << uri if uri
        elsif (match = line.match(DISALLOW))
          path = match[1].to_s.strip
          disallowed << path unless path.empty?
        end
      end
      { sitemaps: sitemaps.uniq, disallowed: disallowed.uniq }
    rescue StandardError
      { sitemaps: [], disallowed: [] }
    end

    def parse_sitemap(body, base_uri, host:, limit: 5)
      paths = []
      body.to_s.scan(LOC) do |match|
        raw = CGI.unescapeHTML(match[0].to_s.strip)
        uri = absolute(raw, base_uri)
        next if uri.nil?
        next unless uri.host.to_s.downcase == host.to_s.downcase
        next unless uri.path.to_s.end_with?(".php")
        next unless safe_path?(uri.path)

        paths << uri.path
      end
      paths.uniq.first(limit)
    rescue StandardError
      []
    end

    def absolute(value, base_uri)
      return nil if value.nil? || value.empty?

      uri = URI.join(base_uri.to_s, value.to_s)
      uri.is_a?(URI::HTTP) ? uri : nil
    rescue URI::InvalidURIError
      nil
    end

    def safe_path?(path)
      !path.to_s.match?(UNSAFE)
    end

    def merge_paths(*lists)
      lists.flatten.compact.map(&:to_s).reject(&:empty?).uniq
    end
  end
end
