# frozen_string_literal: true

require "fanotify"

path = ARGV.fetch(0) { abort "usage: #{$PROGRAM_NAME} PATH [LOG]" }
log = File.open(ARGV[1] || "/dev/stdout", "a")
log.sync = true

Fanotify::Notifier.open(class: :notif, report: %i[fid dfid_name]) do |notifier|
  notifier.mark(:add, path, events: %i[open create delete modify event_on_child], only_dir: true)
  notifier.each_event do |event|
    log.puts "pid=#{event.pid} events=#{event.mask.join(',')} name=#{event.name || '-'}"
  end
end
