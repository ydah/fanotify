# frozen_string_literal: true

require "benchmark"
require "fanotify"
require "tmpdir"

count = Integer(ENV.fetch("EVENTS", "10000"))

Dir.mktmpdir("fanotify-benchmark-") do |directory|
  paths = Array.new(count) do |index|
    File.join(directory, index.to_s).tap { |path| File.write(path, "") }
  end

  Fanotify::Notifier.open(class: :notif, report: [:fid]) do |notifier|
    notifier.mark(:add, directory, events: %i[open event_on_child], only_dir: true)
    child = fork { paths.each { |path| File.open(path, &:read) } }
    received = 0
    elapsed = Benchmark.realtime do
      until received >= count
        events = notifier.read_events
        received += events.length
        events.each(&:close)
      end
    end
    Process.wait(child)
    puts format("%d events in %.3fs (%.0f events/s)", received, elapsed, received / elapsed)
  end
end
