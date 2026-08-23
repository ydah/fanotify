#!/bin/sh
set -eu

kver=${KVER:-6.12}
major=${kver%%.*}
minor=${kver#*.}
minor=${minor%%.*}
require_pre_access=0
if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 14 ]; }; then
  require_pre_access=1
fi

exec vng -v -r "v$kver" --user root -- env FANOTIFY_REQUIRE_PRIVILEGED=1 \
  FANOTIFY_REQUIRE_PRE_ACCESS="$require_pre_access" bundle exec rake test:system
