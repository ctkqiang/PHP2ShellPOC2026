#!/usr/bin/env sh
# Build and install php2shell-poc2026 from this checkout.
#
#   ./install.sh              # install for the current Ruby
#   ./install.sh --user       # install into the user gem directory
#   ./install.sh --uninstall  # remove the installed gem
#
# The gem has no runtime dependencies; only Ruby and RubyGems are required.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

MODE="system"
case "${1:-}" in
  --user) MODE="user" ;;
  --uninstall)
    gem uninstall php2shell_poc2026
    exit 0
    ;;
  --help|-h)
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  "")
    ;;
  *)
    echo "unknown option: $1" >&2
    exit 1
    ;;
esac

command -v ruby >/dev/null 2>&1 || { echo "ruby is required" >&2; exit 1; }
command -v gem  >/dev/null 2>&1 || { echo "gem is required" >&2; exit 1; }

echo "Ruby: $(ruby -v)"
echo "Building gem..."
gem build php2shell_poc2026.gemspec

GEM_FILE=$(ls -1t php2shell_poc2026-*.gem | head -n 1)
if [ "$MODE" = "user" ]; then
  gem install --user-install --local "$GEM_FILE"
else
  gem install --local "$GEM_FILE"
fi

rm -f "$GEM_FILE"

echo
echo "Installed. Try:"
echo "  php2shell --version"
echo "  php2shell --dry-run https://example.com/"
echo
echo "If your shell cannot find the executable, add the Ruby gem bin directory"
echo "to PATH (gem env | grep 'EXECUTABLE DIRECTORY')."
