# frozen_string_literal: true

require "fanotify"

path = ARGV.fetch(0) { abort "usage: sudo #{$PROGRAM_NAME} FILE" }
payload = ENV.fetch("LAZY_PAYLOAD", "materialized by fanotify\n").b
abort "LAZY_PAYLOAD must not be empty" if payload.empty?

Fanotify::Notifier.open(
  class: :pre_content,
  event_flags: %i[rdwr largefile cloexec],
  response_timeout: 5.0
) do |notifier|
  notifier.mark(:add, path, events: [:pre_access])
  notifier.each_event do |event|
    file = event.file
    next unless file&.stat&.zero?

    remaining = event.range_count || payload.bytesize
    file.seek(event.range_offset || 0)
    while remaining.positive?
      chunk = payload.byteslice(0, [remaining, payload.bytesize].min)
      file.write(chunk)
      remaining -= chunk.bytesize
    end
    file.flush
    event.allow!
  end
end
