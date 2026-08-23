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
    FID_EVENTS = %i[attrib create delete delete_self moved_from moved_to move_self rename].freeze
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
      nonblock = options.key?(:nonblock) ? options.delete(:nonblock) : false
      @nonblock = nonblock
      unlimited_queue = options.key?(:unlimited_queue) ? options.delete(:unlimited_queue) : false
      unlimited_marks = options.key?(:unlimited_marks) ? options.delete(:unlimited_marks) : false
      audit = options.key?(:audit) ? options.delete(:audit) : false
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
      unless @on_overflow.nil? || @on_overflow.respond_to?(:call)
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
      @readers = {}
      @readers_condition = ConditionVariable.new
      @closing = false
      @exclude_self = false
    end

    def mark(action, path, events:, on: :inode, follow: true, only_dir: false)
      unless [follow, only_dir].all? { |value| value == true || value == false }
        raise ArgumentError, "follow and only_dir must be true or false"
      end
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

      buffer = read_buffer(timeout)
      return [] unless buffer

      begin
        events = Event.__send__(:parse_owned, buffer, notifier: self)
      rescue Exception # Closing the group releases permission events that could not be parsed.
        begin
          close
        rescue Exception
          nil
        end
        raise
      end
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
        @pending.values.filter_map { |reference, _deadline| dereference(reference) }
      end
    end

    def to_io
      @response_mutex.synchronize do
        raise Error, "notifier is closed" if @closing || closed?

        @io = @handle.to_io.dup unless @io && !@io.closed?
        @io
      end
    end

    def fileno = @handle.fileno
    def closed? = @handle.closed?

    def close
      close_token = Object.new
      @response_mutex.synchronize do
        return if @closing || closed?

        @closing = close_token
        @readers.each_key do |reader|
          reader.raise(Error, "notifier is closed") unless reader == Thread.current
        rescue ThreadError
          nil
        end
      end
      @response_mutex.synchronize do
        @readers_condition.wait(@response_mutex) while @readers.any? { |reader, _| reader != Thread.current }
      end

      if @watchdog && @watchdog != Thread.current
        @watchdog.kill
        @watchdog.join
        @watchdog = nil
      end
      pending_events.each { |event| finish_event(event, :allow, suppress_errors: true) }
      @pending_mutex.synchronize { @pending.keys }.each { |token| finalize_deferred(token) }
      nil
    ensure
      if @closing.equal?(close_token)
        active_error = $!
        close_error = nil
        @response_mutex.synchronize do
          [@io, @handle].each do |resource|
            resource&.close unless resource&.closed?
          rescue StandardError => error
            close_error ||= error
          end
        end
        raise close_error if !active_error && close_error
      end
    end

    private

    def read_buffer(timeout)
      reader = Thread.current
      Thread.handle_interrupt(Exception => :never) do
        @response_mutex.synchronize do
          raise Error, "notifier is closed" if @closing || closed?

          @readers[reader] = true
        end
        begin
          Thread.handle_interrupt(Exception => :on_blocking) { @handle.read(timeout) }
        ensure
          @response_mutex.synchronize do
            @readers.delete(reader)
            @readers_condition.broadcast
          end
        end
      end
    end

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

    def register_pending(event, event_fd, descriptors)
      deadline = monotonic_time + @response_timeout if @response_timeout
      reference = WeakRef.new(event)
      token = Object.new
      @response_mutex.synchronize do
        raise Error, "notifier is closed" if @closing || closed?

        @pending_mutex.synchronize do
          @pending[token] = [reference, deadline, event_fd, descriptors]
        end
        start_watchdog
      end
      token
    rescue Exception # Interrupt must not leave a permission event tracked but undeferred.
      @pending_mutex.synchronize { @pending.delete(token) } if token
      raise
    end

    def unregister_pending(token)
      @pending_mutex.synchronize { @pending.delete(token) } if token
    end

    def finalize_deferred(token)
      entry = @pending_mutex.synchronize { @pending.delete(token) }
      return unless entry

      _reference, _deadline, event_fd, descriptors = entry
      @response_mutex.synchronize { @handle.respond(event_fd, FAN_ALLOW) unless closed? }
      safely_warn "fanotify deferred event was garbage collected; allowing it"
    rescue StandardError => error
      safely_warn "fanotify failed to allow garbage-collected event: #{error.message}"
      begin
        close
      rescue StandardError => close_error
        safely_warn "fanotify failed to close after response error: #{close_error.message}"
      end
    ensure
      descriptors&.each do |descriptor|
        descriptor.close unless descriptor.closed?
      rescue StandardError
        nil
      end
    end

    def start_watchdog
      interval = @response_timeout ? [[@response_timeout / 10.0, 0.01].max, 1.0].min : 0.1
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
        expired, collected = @pending_mutex.synchronize do
          live = []
          dead = []
          @pending.each do |token, (reference, deadline, _event_fd, _descriptors)|
            if (event = dereference(reference))
              live << event if deadline && deadline <= now
            else
              dead << token
            end
          end
          [live, dead]
        end
        collected.each { |token| finalize_deferred(token) }
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

    def dereference(reference)
      reference.__getobj__
    rescue WeakRef::RefError
      nil
    end

    def safely_warn(message)
      warn message
    rescue Exception # Warning failures must not kill the fail-open watchdog.
      nil
    end

    def validate_report!
      unknown = @report - REPORT_FLAGS.keys
      raise ArgumentError, "unknown report flags: #{unknown.join(', ')}" unless unknown.empty?
      flags = flags_for(@report, REPORT_FLAGS, "report")
      if @class != :notif && (@report & %i[fid dir_fid name dfid_name target_fid]).any?
        raise ArgumentError, "FID reporting requires :notif class"
      end
      if (@report & %i[tid pidfd]).length == 2
        raise ArgumentError, ":tid and :pidfd cannot be combined"
      end
      if (flags & FAN_REPORT_NAME).positive? && (flags & FAN_REPORT_DIR_FID).zero?
        raise ArgumentError, ":name requires :dir_fid"
      end
      return unless (flags & FAN_REPORT_TARGET_FID).positive? &&
        (flags & FAN_REPORT_DFID_NAME) != FAN_REPORT_DFID_NAME

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
      if mark.on == :mount && (mark.events & FID_EVENTS).any?
        raise ArgumentError, "#{(mark.events & FID_EVENTS).join(', ')} cannot use a mount mark"
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
