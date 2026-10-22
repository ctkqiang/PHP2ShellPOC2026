# frozen_string_literal: true

module PHP2ShellPOC2026
  VERSION = "2.2.0"

  # Identifies us in every request. Being recognisable is a feature, not a
  # bug: a defender seeing this User-Agent in their logs should be able to
  # Google it and land on this README.
  USER_AGENT = "php2shell-poc2026/#{VERSION} (passive PHP2Shell exposure analyzer)"
end
