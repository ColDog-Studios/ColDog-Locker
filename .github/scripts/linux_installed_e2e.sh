#!/usr/bin/env bash
# Run only inside a disposable root container with /packages and /review-scripts mounted.
set -euo pipefail
format=${1:?Expected deb or rpm}
expected_arch=${2:-x64}
case "$expected_arch" in
  x64|arm64) ;;
  *) echo "Expected architecture x64 or arm64." >&2; exit 2 ;;
esac
case "$format" in
  deb)
    packages=(/packages/ColDogLocker-*-linux-"$expected_arch".deb)
    [[ ${#packages[@]} == 1 && -f ${packages[0]} ]]
    apt-get update
    apt-get install -y "${packages[0]}" python3 xvfb xauth
    ;;
  rpm)
    packages=(/packages/ColDogLocker-*-linux-"$expected_arch".rpm)
    [[ ${#packages[@]} == 1 && -f ${packages[0]} ]]
    dnf install -y "${packages[0]}" python3 xorg-x11-server-Xvfb xorg-x11-xauth shadow-utils util-linux
    ;;
  *) exit 2 ;;
esac
[[ ${#packages[@]} == 1 && -f ${packages[0]} ]]
useradd -m reviewer
cdlocker --version
actual_arch=$(cdlocker dev | awk -F': ' '/^Architecture:/ {print tolower($2)}')
[[ $actual_arch == "$expected_arch" ]]
runuser -u reviewer -- python3 /review-scripts/cli_e2e.py --cli /usr/bin/cdlocker --work-dir /home/reviewer/review-work
# Exercise the packaged GUI's native dependency loading under an X server.
# Staying alive is a smoke check, not an accessibility or interaction test.
set +e
runuser -u reviewer -- timeout 10s xvfb-run -a /opt/coldog-locker/ColDogLocker > /tmp/gui-smoke.log 2>&1
status=$?
set -e
cat /tmp/gui-smoke.log
[[ $status == 124 ]]
runuser -u reviewer -- touch /home/reviewer/preserve-on-uninstall
case "$format" in
  deb)
    apt-get install --reinstall -y "${packages[0]}"
    cdlocker --version
    apt-get purge -y coldog-locker
    ;;
  rpm)
    dnf reinstall -y "${packages[0]}"
    cdlocker --version
    dnf remove -y coldog-locker
    ;;
esac
[[ ! -e /usr/bin/cdlocker && ! -e /opt/coldog-locker/ColDogLocker ]]
[[ -f /home/reviewer/preserve-on-uninstall ]]
echo 'Installed CLI, GUI smoke, reinstall, and uninstall checks passed.'
