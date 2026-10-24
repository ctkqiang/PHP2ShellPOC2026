# frozen_string_literal: true

module PHP2ShellPOC2026
  VERSION = "3.0.0"

  HOMEPAGE = "https://github.com/ctkqiang/PHP2ShellPOC2026"

  # Identifies us in every request. Being recognisable is a feature, not a
  # bug: a defender seeing this User-Agent in their logs should be able to
  # find the project and understand exactly what was sent.
  USER_AGENT = "php2shell-poc2026/#{VERSION} " \
               "(+#{HOMEPAGE}; passive authorized assessment)"

  # Opt-in compatibility User-Agent for hosts whose bot protection rejects
  # the identifying string before the application answers. This is not the
  # default: it can cross a control boundary, so the operator has to ask for
  # it explicitly and is told to confirm authorization first.
  BROWSER_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " \
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
end
