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
    target_fid: FAN_REPORT_TARGET_FID | FAN_REPORT_FID,
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

  # Owns a fanotify group and provides safe event iteration.
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
      event_flags = Array(options.delete(:event_flags) || %i[rdonly largefile cloexec]).map(&:to_sym)
      @on_overflow = options.delete(:on_overflow)
      @on_error = options.delete(:on_error)
      @on_error = @on_error.nil? ? :allow : @on_error
      @on_error = @on_error.to_sym if @on_error.respond_to?(:to_sym)
      @response_timeout = options.key?(:response_timeout) ? options.delete(:response_timeout) : 5.0
      raise ArgumentError, "unknown options: #{options.keys.join(', ')}" unless options.empty?
      unless [nonblock, unlimited_queue, unlimited_marks, audit].all? { |value| value == true || value == false }
        raise ArgumentError, "boolean options must be true or false"
      end
      if @on_overflow && !@on_overflow.respond_to?(:call)
        raise ArgumentError, "on_overflow must be callable or nil"
      end
      raise ArgumentError, "on_error must be :allow or :deny" unless %i[allow deny].include?(@on_error)
      unless @response_timeout.nil? || (@response_timeout.is_a?(Numeric) && @response_timeout.real? &&
        @response_timeout.finite? && @response_timeout.positive?)
        raise ArgumentError, "response_timeout must be positive or nil"
      end

      @class = klass.to_sym
      validate_report!
      access_modes = event_flags & %i[rdonly wronly rdwr]
      raise ArgumentError, "event_flags require exactly one access mode" unless access_modes.one?
      flags = fetch(CLASS_FLAGS, @class, "class") | flags_for(@report, REPORT_FLAGS, "report")
      flags |= FAN_NONBLOCK if nonblock
      flags |= FAN_UNLIMITED_QUEUE if unlimited_queue
      flags |= FAN_UNLIMITED_MARKS if unlimited_marks
      flags |= FAN_ENABLE_AUDIT if audit
      @handle = Native.open(flags, flags_for(event_flags, EVENT_FLAGS, "event flag"))
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
      unless timeout.nil? || (timeout.is_a?(Numeric) && timeout.real? && timeout.finite? &&
        timeout >= 0 && timeout * 1000 <= 2_147_483_647)
        raise ArgumentError, "timeout must be a non-negative finite number or nil"
      end

      buffer = @handle.read(timeout)
      return [] unless buffer

      events = Event.__send__(:parse_owned, buffer, notifier: self)
      begin
        events.each do |event|
          next unless event.overflow?

          safely_warn "fanotify event queue overflowed; events were lost"
          @on_overflow&.call(event)
        end
      rescue Exception # SystemExit and Interrupt must not strand permission events.
        events.each { |event| finish_event(event, :allow, suppress_errors: true) }
        raise
      end
      events
    end

    def each_event
      return enum_for(__method__) unless block_given?

      loop do
        events = read_events(timeout: @nonblock ? 0.1 : nil)
        begin
          events.each do |event|
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
        ensure
          events.each do |event|
            finish_event(event, :allow, suppress_errors: true) unless event.closed? || event.deferred?
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
      pending_events.each { |event| finish_event(event, :allow, suppress_errors: true) }
    ensure
      @handle.close unless @handle.closed?
    end

    private

    def finish_event(event, decision, suppress_errors: false)
      responded = false
      begin
        if event.permission? && !event.responded?
          event.public_send("#{decision}!")
          responded = true
        end
      ensure
        event.close
      end
      responded
    rescue StandardError => response_error
      raise unless suppress_errors

      safely_warn "fanotify failed to #{decision} event: #{response_error.message}"
      false
    end

    def respond_to_event(event_fd, response)
      @response_mutex.synchronize { @handle.respond(event_fd, response) }
    end

    def register_pending(event, event_fd, event_descriptor)
      deadline = monotonic_time + @response_timeout if @response_timeout
      reference = WeakRef.new(event)
      @pending_mutex.synchronize { @pending[event.object_id] = [reference, deadline] }
      ObjectSpace.define_finalizer(event, deferred_finalizer(event.object_id, event_fd, event_descriptor))
      start_watchdog if @response_timeout
    rescue Exception # Interrupt must not leave a permission event tracked but undeferred.
      @pending_mutex.synchronize { @pending.delete(event.object_id) }
      ObjectSpace.undefine_finalizer(event)
      raise
    end

    def unregister_pending(event)
      @pending_mutex.synchronize { @pending.delete(event.object_id) }
      ObjectSpace.undefine_finalizer(event)
    end

    def deferred_finalizer(object_id, event_fd, event_descriptor)
      notifier = WeakRef.new(self)
      proc do
        notifier.__getobj__.__send__(:finalize_deferred, object_id, event_fd)
      rescue WeakRef::RefError
        nil
      ensure
        event_descriptor&.close unless event_descriptor&.closed?
      end
    end

    def finalize_deferred(object_id, event_fd)
      entry = @pending_mutex.synchronize { @pending.delete(object_id) }
      return unless entry

      @response_mutex.synchronize { @handle.respond(event_fd, FAN_ALLOW) unless closed? }
      safely_warn "fanotify deferred event was garbage collected; allowing it"
    rescue WeakRef::RefError, IOError, SystemCallError
      nil
    end

    def start_watchdog
      interval = [[@response_timeout / 10.0, 0.01].max, 1.0].min
      @pending_mutex.synchronize do
        return if @watchdog&.alive?

        @watchdog = Thread.new { watchdog_loop(interval) }
        @watchdog.name = "fanotify-response-watchdog" if @watchdog.respond_to?(:name=)
      end
    end

    def watchdog_loop(interval)
      loop do
        sleep interval
        now = monotonic_time
        expired = @pending_mutex.synchronize do
          @pending.values.filter_map do |reference, deadline|
            reference.__getobj__ if deadline <= now && reference.weakref_alive?
          end
        end
        expired.each do |event|
          if finish_event(event, :allow, suppress_errors: true)
            safely_warn "fanotify response timeout expired; allowing event"
          end
        end
        stop = @pending_mutex.synchronize do
          @watchdog = nil if @pending.empty?
          @pending.empty?
        end
        break if stop
      end
    end

    def monotonic_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def safely_warn(message)
      warn message
    rescue StandardError
      nil
    end

    def validate_report!
      unknown = @report - REPORT_FLAGS.keys
      raise ArgumentError, "unknown report flags: #{unknown.join(', ')}" unless unknown.empty?
      if @class != :notif && (@report & %i[fid dir_fid name dfid_name target_fid]).any?
        raise ArgumentError, "FID reporting requires :notif class"
      end
      if (@report & %i[tid pidfd]).length == 2
        raise ArgumentError, ":tid and :pidfd cannot be combined"
      end
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
      if mark.events.include?(:pre_access) && @class != :pre_content
        raise ArgumentError, "pre_access requires :pre_content class"
      end
      raise ArgumentError, "overflow is receive-only" if mark.events.include?(:overflow)
      if mark.events.include?(:event_on_child) && mark.on != :inode
        raise ArgumentError, "event_on_child requires an inode mark"
      end
      if mark.events.include?(:fs_error) && (mark.on != :filesystem || !fid_reporting?)
        raise ArgumentError, "fs_error requires filesystem mark and FID reporting"
      end
      return if (mark.events & FID_EVENTS).empty? || (@report & %i[fid dir_fid dfid_name]).any?

      raise ArgumentError, "#{(mark.events & FID_EVENTS).join(', ')} require FID reporting"
    end

    def flags_for(names, mapping, label)
      names.reduce(0) { |flags, name| flags | fetch(mapping, name.to_sym, label) }
    end

    def fid_reporting? = (flags_for(@report, REPORT_FLAGS, "report") & FAN_REPORT_FID).positive?

    def fetch(mapping, name, label)
      mapping.fetch(name) { raise ArgumentError, "unknown #{label}: #{name.inspect}" }
    end
  end
end
