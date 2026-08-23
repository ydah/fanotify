#!/bin/sh
set -eu

exec vng -v -r "v${KVER:-6.12}" -- bundle exec rake test:system
