#!/bin/sh
# This source-managed fork intentionally disables the upstream installer.
set -eu
printf '%s\n' 'Installation is disabled for this fork. Build from source with Go 1.27.3:' '  git clone https://github.com/punnkrit/line-scheduler-client.git' '  cd line-scheduler-client' '  go mod verify' '  ./build.sh' 'No upstream release was downloaded or installed.' >&2
exit 1
