# frozen_string_literal: true

require "fanotify"

path = ARGV.fetch(0) { abort "usage: sudo #{$PROGRAM_NAME} FILE" }
payload = ENV.fetch("LAZY_PAYLOAD", "materialized by fanotify\n").b

Fanotify::Notifier.open(
  class: :pre_content,
  event_flags: %i[rdwr largefile cloexec],
  response_timeout: 5.0
) do |notifier|
  notifier.mark(:add, path, events: [:pre_access])
  notifier.each_event do |event|
    next unless event.file&.stat&.zero?

    event.file.write(payload)
    event.file.flush
    event.allow!
  end
end
