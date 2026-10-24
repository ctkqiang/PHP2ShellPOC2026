# frozen_string_literal: true

module PHP2ShellPOC2026
  VERSION = "3.0.0"

  HOMEPAGE = "https://github.com/ctkqiang/PHP2ShellPOC2026"

  # Identifies us in every request. Being recognisable is a feature, not a
  # bug: a defender seeing this User-Agent in their logs should be able to
  # find the project and understand exactly what was sent.
  USER_AGENT = "php2shell-poc2026/#{VERSION} " \
               "(+#{HOMEPAGE}; passive authorized assessment)"
end
