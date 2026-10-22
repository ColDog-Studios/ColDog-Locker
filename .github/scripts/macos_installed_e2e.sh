#!/usr/bin/env bash
set -euo pipefail

package=${1:?Expected a PKG path}
review_scripts=${2:?Expected the review scripts directory}
expected_arch=${3:?Expected x64 or arm64}
package=$(cd "$(dirname "$package")" && pwd)/$(basename "$package")
review_scripts=$(cd "$review_scripts" && pwd)

signature=$(pkgutil --check-signature "$package" 2>&1 || true)
grep -qi 'no signature' <<<"$signature"

sudo installer -pkg "$package" -target /
cli=/usr/local/bin/cdlocker
gui='/Applications/ColDog Locker.app/Contents/MacOS/ColDogLocker'
[[ -x "$cli" && -x "$gui" ]]

actual_arch=$($cli dev | awk -F': ' '/^Architecture:/ {print tolower($2)}')
case "$expected_arch" in
  x64) [[ $actual_arch == x64 ]] ;;
  arm64) [[ $actual_arch == arm64 ]] ;;
  *) exit 2 ;;
esac

python3 "$review_scripts/cli_e2e.py" --cli "$cli" --work-dir "$RUNNER_TEMP/cdlocker-installed-e2e"

gui_log="$RUNNER_TEMP/coldog-locker-gui.log"
"$gui" >"$gui_log" 2>&1 &
gui_pid=$!
sleep 8
if ! kill -0 "$gui_pid" 2>/dev/null; then
  wait "$gui_pid" || status=$?
  cat "$gui_log"
  echo "Installed GUI exited during startup with code ${status:-0}." >&2
  exit 1
fi
kill "$gui_pid"
wait "$gui_pid" || true

marker="$HOME/Library/Application Support/ColDog Studios/ColDog Locker/preserve-on-uninstall"
mkdir -p "$(dirname "$marker")"
touch "$marker"
sudo installer -pkg "$package" -target /
$cli --version >/dev/null

sudo rm -rf '/Applications/ColDog Locker.app'
sudo rm -f /usr/local/bin/cdlocker /usr/local/share/man/man1/cdlocker.1.gz
sudo pkgutil --forget com.coldogstudios.coldog-locker >/dev/null || true
[[ ! -e "$cli" && ! -e "$gui" && -f "$marker" ]]
rm -f "$marker"

echo 'Installed macOS CLI, GUI startup, reinstall, unsigned-package, and manual uninstall checks passed.'
