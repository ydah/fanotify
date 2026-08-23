#!/usr/bin/env bash
set -euo pipefail

if [[ ${FANOTIFY_REQUIRE_PRE_ACCESS:-0} == 1 ]]; then
  truncate -s 64M /tmp/fanotify-pre-access.ext4
  mkfs.ext4 -q -F /tmp/fanotify-pre-access.ext4
  mkdir -p /mnt/fanotify-pre-access
  mount -o loop /tmp/fanotify-pre-access.ext4 /mnt/fanotify-pre-access
  export TMPDIR=/mnt/fanotify-pre-access
fi

bundle exec rake compile test:system
