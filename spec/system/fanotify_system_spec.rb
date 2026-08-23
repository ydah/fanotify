# frozen_string_literal: true

require "fileutils"
require "timeout"
require "tmpdir"

RSpec.describe "fanotify system integration" do
  before do
    skip "Linux only" unless RUBY_PLATFORM.include?("linux")
    skip "fanotify is unavailable" unless Fanotify.supported?

    @directory = Dir.mktmpdir("fanotify-system-")
    @path = File.join(@directory, "payload")
    File.write(@path, "payload")
  end

  after do
    @notifier&.close
    FileUtils.remove_entry(@directory) if @directory && File.exist?(@directory)
  end

  def permission_notifier(response_timeout: 1.0, on_error: :allow, report: [])
    @notifier = Fanotify::Notifier.new(class: :content, response_timeout:, on_error:, report:)
    @notifier.mark(:add, @directory, events: %i[open_perm event_on_child], only_dir: true)
    @notifier
  rescue Errno::EPERM, Errno::EACCES => error
    skip "CAP_SYS_ADMIN is required: #{error.message}"
  end

  def fork_read
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      result = File.read(@path)
      writer.write("ok:#{result}")
    rescue StandardError => error
      writer.write("error:#{error.class.name}")
    ensure
      writer.close
      exit!
    end
    writer.close
    [pid, reader]
  end

  def wait_for_child(pid, reader)
    Timeout.timeout(5) { reader.readpartial(4096) }.tap { Process.wait(pid) }
  ensure
    reader.close
    begin
      Process.kill(:KILL, pid) unless Process.waitpid(pid, Process::WNOHANG)
      Process.wait(pid)
    rescue Errno::ECHILD, Errno::ESRCH
      nil
    end
  end

  def next_permission_event(notifier)
    Timeout.timeout(3) do
      loop do
        event = notifier.read_events(timeout: 1).find(&:permission?)
        return event if event
      end
    end
  end

  def defer_next_permission_event(notifier)
    next_permission_event(notifier).defer!
    nil
  end

  it "receives open notifications" do
    @notifier = Fanotify::Notifier.new(class: :notif, report: [:fid])
    @notifier.mark(:add, @directory, events: %i[open event_on_child], only_dir: true)
    pid, reader = fork_read
    event = Timeout.timeout(3) do
      loop do
        found = @notifier.read_events(timeout: 1).find { |item| item.mask.include?(:open) }
        break found if found
      end
    end

    expect(event.pid).to eq(pid)
    expect(wait_for_child(pid, reader)).to eq("ok:payload")
    event.close
  rescue Errno::EPERM, Errno::EACCES => error
    skip "fanotify notification permission denied: #{error.message}"
  end

  it "releases the GVL and interrupts a blocking read" do
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      notifier = Fanotify::Notifier.new(class: :notif, report: [:fid])
      read_thread = Thread.new { notifier.read_events }
      Thread.pass until read_thread.status == "sleep"
      read_thread.kill
      read_thread.join
      writer.write("gvl:interruptible")
    ensure
      notifier&.close
      writer.close
      exit!
    end
    writer.close

    expect(wait_for_child(pid, reader)).to eq("gvl:interruptible")
  end

  it "processes an event with GC stress enabled" do
    previous_stress = GC.stress
    GC.stress = true
    @notifier = Fanotify::Notifier.new(class: :notif, report: [:fid])
    @notifier.mark(:add, @directory, events: %i[open event_on_child], only_dir: true)
    pid, reader = fork_read
    event = Timeout.timeout(5) do
      loop do
        found = @notifier.read_events(timeout: 1).find { |item| item.mask.include?(:open) }
        break found if found
      end
    end

    event.close
    expect(wait_for_child(pid, reader)).to eq("ok:payload")
  ensure
    GC.stress = previous_stress
  end

  it "reports created names through DFID records" do
    @notifier = Fanotify::Notifier.new(class: :notif, report: %i[fid dfid_name])
    @notifier.mark(:add, @directory, events: %i[create event_on_child], only_dir: true)

    File.write(File.join(@directory, "created"), "data")
    event = Timeout.timeout(3) do
      loop do
        found = @notifier.read_events(timeout: 1).find { |item| item.mask.include?(:create) }
        break found if found
      end
    end

    expect(event.name).to eq("created")
    expect(event.dfid).to be_a(Fanotify::FileHandle)
    event.close
  rescue Errno::EPERM, Errno::EACCES => error
    skip "fanotify FID permission denied: #{error.message}"
  end

  it "reports both names and the target FID for renames" do
    @notifier = Fanotify::Notifier.new(class: :notif, report: %i[dfid_name target_fid])
    @notifier.mark(:add, @directory, events: %i[rename event_on_child], only_dir: true)

    File.rename(@path, File.join(@directory, "renamed"))
    event = Timeout.timeout(3) do
      loop do
        found = @notifier.read_events(timeout: 1).find { |item| item.mask.include?(:rename) }
        break found if found
      end
    end

    expect(event).to have_attributes(old_name: "payload", new_name: "renamed")
    expect(event.fid).to be_a(Fanotify::FileHandle)
    event.close
  rescue Errno::EINVAL => error
    skip "FAN_RENAME target FID is unavailable: #{error.message}"
  end

  it "creates an unprivileged FID notifier" do
    File.chmod(0o755, @directory)
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      Process::GID.change_privilege(65_534)
      Process::UID.change_privilege(65_534)
      notifier = Fanotify::Notifier.new(class: :notif, report: [:fid])
      notifier.mark(:add, @path, events: [:open])
      writer.write("ok")
    rescue StandardError => error
      writer.write("#{error.class}:#{error.message}")
    ensure
      notifier&.close
      writer.close
      exit!
    end

    expect(wait_for_child(pid, reader)).to eq("ok")
  end

  it "does not leak descriptors across 10,000 fd events" do
    permission_notifier(response_timeout: nil)
    baseline = Dir.children("/proc/self/fd").length
    pid = fork do
      10_000.times { File.open(@path, &:read) }
      exit!
    end

    Timeout.timeout(30) do
      10_000.times { next_permission_event(@notifier).close }
      Process.wait(pid)
    end
    GC.start

    expect(Dir.children("/proc/self/fd").length).to be <= baseline
  ensure
    begin
      Process.kill(:KILL, pid) if pid
    rescue Errno::ESRCH
      nil
    end
  end

  it "reports queue overflow" do
    paths = Array.new(18_000) { |index| File.join(@directory, "overflow-#{index}") }
    paths.each { |path| File.write(path, "") }
    @notifier = Fanotify::Notifier.new(class: :notif, report: [:fid], nonblock: true)
    @notifier.mark(:add, @directory, events: %i[open event_on_child], only_dir: true)
    pid = fork do
      paths.each { |path| File.open(path, &:read) }
      exit!
    end
    Timeout.timeout(10) { Process.wait(pid) }

    overflow = nil
    expect do
      Timeout.timeout(10) do
        loop do
          events = @notifier.read_events(timeout: 0.1)
          overflow ||= events.find(&:overflow?)
          events.each(&:close)
          break if events.empty?
        end
      end
    end.to output(/event queue overflowed/).to_stderr_from_any_process
    expect(overflow).to be_overflow
  ensure
    begin
      Process.kill(:KILL, pid) if pid
    rescue Errno::ESRCH
      nil
    end
  end

  it "denies child access" do
    notifier = permission_notifier
    pid, reader = fork_read
    next_permission_event(notifier).deny!

    expect(wait_for_child(pid, reader)).to eq("error:Errno::EPERM")
  end

  it "owns and closes reported PIDFDs" do
    notifier = permission_notifier(report: [:pidfd])
    pid, reader = fork_read
    event = next_permission_event(notifier)

    expect(event.pidfd).to be_a(Integer)
    expect(File.readlink("/proc/self/fd/#{event.pidfd}")).to include("pidfd")
    event.allow!
    expect(wait_for_child(pid, reader)).to eq("ok:payload")
    pidfd = event.pidfd
    event.close
    expect { IO.for_fd(pidfd, autoclose: false).stat }.to raise_error(Errno::EBADF)
  end

  it "materializes the requested pre-access range" do
    @notifier = Fanotify::Notifier.new(
      class: :pre_content,
      event_flags: %i[rdwr largefile cloexec],
      response_timeout: 1.0
    )
    @notifier.mark(:add, @path, events: [:pre_access])
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      writer.write("ok:#{File.open(@path) { |file| file.read(4) }}")
    rescue StandardError => error
      writer.write("error:#{error.class.name}")
    ensure
      writer.close
      exit!
    end
    writer.close
    event = next_permission_event(@notifier)

    expect(event).to have_attributes(range_offset: 0, range_count: 4)
    event.file.write("data")
    event.file.flush
    event.allow!
    expect(wait_for_child(pid, reader)).to eq("ok:data")
    event.close
  rescue Errno::EINVAL => error
    skip "FAN_PRE_ACCESS requires Linux 6.14+: #{error.message}"
  end

  it "automatically allows when a handler returns" do
    notifier = permission_notifier
    pid, reader = fork_read

    Timeout.timeout(3) { catch(:handled) { notifier.each_event { throw :handled } } }

    expect(wait_for_child(pid, reader)).to eq("ok:payload")
  end

  it "allows before propagating a handler exception" do
    notifier = permission_notifier
    pid, reader = fork_read

    expect do
      Timeout.timeout(3) { notifier.each_event { raise "handler failed" } }
    end.to raise_error("handler failed")
    expect(wait_for_child(pid, reader)).to eq("ok:payload")
  end

  it "allows a deferred event after its response timeout" do
    notifier = permission_notifier(response_timeout: 0.1)
    pid, reader = fork_read
    next_permission_event(notifier).defer!

    expect { expect(wait_for_child(pid, reader)).to eq("ok:payload") }
      .to output(/response timeout expired/).to_stderr_from_any_process
  end

  it "allows a deferred event when it is garbage collected" do
    notifier = permission_notifier(response_timeout: nil)
    pid, reader = fork_read
    Thread.new { defer_next_permission_event(notifier) }.join

    expect do
      3.times { GC.start }
    end.to output(/garbage collected; allowing/).to_stderr_from_any_process
    expect(wait_for_child(pid, reader)).to eq("ok:payload")
  end
end
