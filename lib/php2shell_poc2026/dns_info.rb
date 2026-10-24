# frozen_string_literal: true

require "ipaddr"
require "resolv"
require "timeout"

module PHP2ShellPOC2026
  # Passive DNS context. Addresses are useful for asset inventory and for
  # spotting a CDN/origin split; no reverse lookup is performed because it
  # adds latency and rarely changes the verdict.
  module DnsInfo
    module_function

    def lookup(host, timeout: 2)
      text = host.to_s.sub(/\A\[/, "").sub(/\]\z/, "")
      begin
        address = IPAddr.new(text)
        return { addresses: [address.to_s], ip: true, error: nil }
      rescue IPAddr::InvalidAddressError, ArgumentError
        # Not an IP; resolve it.
      end

      addresses = Timeout.timeout(timeout) { Resolv.getaddresses(text) }
      { addresses: addresses.uniq.sort, ip: false, error: nil }
    rescue Timeout::Error
      { addresses: [], ip: false, error: "DNS lookup timed out" }
    rescue StandardError => e
      { addresses: [], ip: false, error: "#{e.class}: #{e.message}" }
    end
  end
end
