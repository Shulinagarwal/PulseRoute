#!/bin/sh
set -eu
root="$(cd "$(dirname "$0")" && pwd)"
for component in publisher worker replay; do
  docker build --target "$component" \
    -t "111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-$component:2" "$root"
done
