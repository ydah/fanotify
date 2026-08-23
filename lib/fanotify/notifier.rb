# frozen_string_literal: true

module Fanotify
  CLASS_FLAGS = {
    notif: FAN_CLASS_NOTIF,
    content: FAN_CLASS_CONTENT,
    pre_content: FAN_CLASS_PRE_CONTENT
  }.freeze

  REPORT_FLAGS = {
    tid: FAN_REPORT_TID,
    fid: FAN_REPORT_FID,
    dir_fid: FAN_REPORT_DIR_FID,
    name: FAN_REPORT_NAME,
    dfid_name: FAN_REPORT_DFID_NAME,
    target_fid: FAN_REPORT_TARGET_FID,
    pidfd: FAN_REPORT_PIDFD
  }.freeze

  EVENT_FLAGS = {
    rdonly: O_RDONLY,
    wronly: O_WRONLY,
    rdwr: O_RDWR,
    largefile: O_LARGEFILE,
    cloexec: O_CLOEXEC,
    nonblock: O_NONBLOCK
  }.freeze

  EVENT_MASKS = {
    access: FAN_ACCESS,
    modify: FAN_MODIFY,
    attrib: FAN_ATTRIB,
    close_write: FAN_CLOSE_WRITE,
    close_nowrite: FAN_CLOSE_NOWRITE,
    open: FAN_OPEN,
    moved_from: FAN_MOVED_FROM,
    moved_to: FAN_MOVED_TO,
    create: FAN_CREATE,
    delete: FAN_DELETE,
    delete_self: FAN_DELETE_SELF,
    move_self: FAN_MOVE_SELF,
    open_exec: FAN_OPEN_EXEC,
    overflow: FAN_Q_OVERFLOW,
    fs_error: FAN_FS_ERROR,
    open_perm: FAN_OPEN_PERM,
    access_perm: FAN_ACCESS_PERM,
    open_exec_perm: FAN_OPEN_EXEC_PERM,
    pre_access: FAN_PRE_ACCESS,
    event_on_child: FAN_EVENT_ON_CHILD,
    rename: FAN_RENAME,
    ondir: FAN_ONDIR
  }.freeze

  class Notifier
    PERMISSION_EVENTS = %i[open_perm access_perm open_exec_perm pre_access].freeze
    PERMISSION_MASK = PERMISSION_EVENTS.reduce(0) { |mask, event| mask | EVENT_MASKS.fetch(event) }
    FID_EVENTS = %i[create delete moved_from moved_to rename].freeze
    MARK_ACTIONS = {add: FAN_MARK_ADD, remove: FAN_MARK_REMOVE}.freeze
    MARK_TARGETS = {inode: FAN_MARK_INODE, mount: FAN_MARK_MOUNT, filesystem: FAN_MARK_FILESYSTEM}.freeze

    attr_reader :report

    def self.open(**options)
      notifier = new(**options)
      return notifier unless block_given?

      begin
        yield notifier
      ensure
        notifier.close
      end
    end

    def initialize(**options)
      klass = options.delete(:class) || :notif
      @report = Array(options.delete(:report)).map(&:to_sym)
      nonblock = options.delete(:nonblock) || false
      @nonblock = nonblock
      unlimited_queue = options.delete(:unlimited_queue) || false
      unlimited_marks = options.delete(:unlimited_marks) || false
      audit = options.delete(:audit) || false
      event_flags = options.delete(:event_flags) || %i[rdonly largefile cloexec]
      @on_overflow = options.delete(:on_overflow)
      @on_error = (options.delete(:on_error) || :allow).to_sym
      @response_timeout = options.key?(:response_timeout) ? options.delete(:response_timeout) : 5.0
      raise ArgumentError, "unknown options: #{options.keys.join(', ')}" unless options.empty?
      raise ArgumentError, "on_error must be :allow or :deny" unless %i[allow deny].include?(@on_error)
      if @response_timeout && !@response_timeout.positive?
        raise ArgumentError, "response_timeout must be positive or nil"
      end

      validate_report!
      @class = klass.to_sym
      flags = fetch(CLASS_FLAGS, @class, "class") | flags_for(@report, REPORT_FLAGS, "report")
      flags |= FAN_NONBLOCK if nonblock
      flags |= FAN_UNLIMITED_QUEUE if unlimited_queue
      flags |= FAN_UNLIMITED_MARKS if unlimited_marks
      flags |= FAN_ENABLE_AUDIT if audit
      @handle = Native.open(flags, flags_for(Array(event_flags), EVENT_FLAGS, "event flag"))
      @pending = {}
      @pending_mutex = Mutex.new
      @response_mutex = Mutex.new
      @exclude_self = false
    end

    def mark(action, path, events:, on: :inode, follow: true, only_dir: false)
      mark = Mark.new(action: action.to_sym, path: File.path(path), events: Array(events).map(&:to_sym),
                      on: on.to_sym, follow:, only_dir:)
      validate_mark!(mark)
      flags = fetch(MARK_ACTIONS, mark.action, "mark action") | fetch(MARK_TARGETS, mark.on, "mark target")
      flags |= FAN_MARK_DONT_FOLLOW unless mark.follow
      flags |= FAN_MARK_ONLYDIR if mark.only_dir
      @handle.mark(flags, flags_for(mark.events, EVENT_MASKS, "event"), AT_FDCWD, mark.path)
      self
    end

    def flush(on = :inode)
      @handle.mark(FAN_MARK_FLUSH | fetch(MARK_TARGETS, on.to_sym, "mark target"), 0, AT_FDCWD, nil)
      self
    end

    def read_events(timeout: nil)
      raise ArgumentError, "timeout must be non-negative" if timeout&.negative?

      buffer = @handle.read(timeout)
      return [] unless buffer

      Event.parse(buffer, notifier: self, own_fds: true).tap do |events|
        events.each { |event| @on_overflow&.call(event) if event.overflow? }
      end
    end

    def each_event
      return enum_for(__method__) unless block_given?

      loop do
        read_events(timeout: @nonblock ? 0.1 : nil).each do |event|
          if @exclude_self && event.pid == Process.pid
            finish_event(event, :allow)
            next
          end

          begin
            yield event
          ensure
            handling_error = !$!.nil?
            if handling_error || !event.deferred?
              finish_event(event, handling_error ? @on_error : :allow, suppress_errors: handling_error)
            end
          end
        end
      end
    end

    def exclude_self!
      @exclude_self = true
      self
    end

    def pending_events
      @pending_mutex.synchronize do
        @pending.delete_if { |_id, (reference, _deadline)| !reference.weakref_alive? }
        @pending.values.filter_map do |reference, _deadline|
          reference.__getobj__ if reference.weakref_alive?
        end
      end
    end

    def to_io = @handle.to_io
    def fileno = @handle.fileno
    def closed? = @handle.closed?

    def close
      return if closed?

      @watchdog&.kill
      @watchdog&.join
      pending_events.each { |event| finish_event(event, :allow) }
      @handle.close
    end

    private

    def finish_event(event, decision, suppress_errors: false)
      event.public_send("#{decision}!") if event.permission? && !event.responded?
      event.close
    rescue StandardError => response_error
      raise unless suppress_errors

      warn "fanotify failed to #{decision} event while handling another error: #{response_error.message}"
    end

    def respond_to_event(event, event_fd, response)
      @response_mutex.synchronize { @handle.respond(event_fd, response) }
      unregister_pending(event)
    end

    def register_pending(event, event_fd)
      deadline = monotonic_time + @response_timeout if @response_timeout
      reference = WeakRef.new(event)
      @pending_mutex.synchronize { @pending[event.object_id] = [reference, deadline] }
      ObjectSpace.define_finalizer(event, deferred_finalizer(event.object_id, event_fd))
      start_watchdog if @response_timeout
    end

    def unregister_pending(event)
      @pending_mutex.synchronize { @pending.delete(event.object_id) }
      ObjectSpace.undefine_finalizer(event)
    end

    def deferred_finalizer(object_id, event_fd)
      notifier = WeakRef.new(self)
      proc { notifier.__getobj__.__send__(:finalize_deferred, object_id, event_fd) rescue nil }
    end

    def finalize_deferred(object_id, event_fd)
      entry = @pending_mutex.synchronize { @pending.delete(object_id) }
      return unless entry

      warn "fanotify deferred event was garbage collected; allowing it"
      @response_mutex.synchronize { @handle.respond(event_fd, FAN_ALLOW) unless closed? }
    rescue WeakRef::RefError, IOError, SystemCallError
      nil
    end

    def start_watchdog
      return if @watchdog&.alive?

      interval = [@response_timeout / 10.0, 0.1].max
      @watchdog = Thread.new do
        loop do
          sleep interval
          now = monotonic_time
          expired = @pending_mutex.synchronize do
            @pending.values.filter_map do |reference, deadline|
              reference.__getobj__ if deadline <= now && reference.weakref_alive?
            end
          end
          expired.each do |event|
            warn "fanotify response timeout expired; allowing event"
            finish_event(event, :allow)
          end
        end
      end
      @watchdog.name = "fanotify-response-watchdog" if @watchdog.respond_to?(:name=)
    end

    def monotonic_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def validate_report!
      unknown = @report - REPORT_FLAGS.keys
      raise ArgumentError, "unknown report flags: #{unknown.join(', ')}" unless unknown.empty?
      raise ArgumentError, ":name requires :dir_fid" if @report.include?(:name) && !@report.include?(:dir_fid)
      return unless @report.include?(:target_fid) && !@report.include?(:dfid_name)

      raise ArgumentError, ":target_fid requires :dfid_name"
    end

    def validate_mark!(mark)
      unknown = mark.events - EVENT_MASKS.keys
      raise ArgumentError, "unknown events: #{unknown.join(', ')}" unless unknown.empty?
      if @class == :notif && (mark.events & PERMISSION_EVENTS).any?
        raise ArgumentError, "permission events require :content or :pre_content class"
      end
      return if (mark.events & FID_EVENTS).empty? || (@report & %i[fid dir_fid dfid_name]).any?

      raise ArgumentError, "#{(mark.events & FID_EVENTS).join(', ')} require FID reporting"
    end

    def flags_for(names, mapping, label)
      names.reduce(0) { |flags, name| flags | fetch(mapping, name.to_sym, label) }
    end

    def fetch(mapping, name, label)
      mapping.fetch(name) { raise ArgumentError, "unknown #{label}: #{name.inspect}" }
    end
  end
end
