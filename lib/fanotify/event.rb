# frozen_string_literal: true

module Fanotify
  # One parsed fanotify event and any descriptors owned by it.
  class Event
    INFO_FID = 1
    INFO_DFID_NAME = 2
    INFO_DFID = 3
    INFO_PIDFD = 4
    INFO_ERROR = 5
    INFO_RANGE = 6
    INFO_OLD_DFID_NAME = 10
    INFO_NEW_DFID_NAME = 12

    attr_reader :raw_mask, :pid, :notifier, :fid, :dfid, :name, :pidfd,
                :pidfd_error, :old_dfid, :old_name, :new_dfid, :new_name,
                :error, :error_count, :range_offset, :range_count

    class << self
      def parse(buffer)
        Native.parse(buffer).map { |attributes| new(attributes) }
      end

      private

      def parse_owned(buffer, notifier:)
        attributes = Native.parse(buffer, true)
        events = []
        attributes.each { |item| events << new(item, notifier:, own_fds: true) }
        events
      rescue Exception # Transferred kernel descriptors must not wait for GC on construction failure.
        events&.each { |event| close_owned(event) }
        attributes&.each do |item|
          close_owned(item[:file_descriptor])
          item.fetch(:infos, []).each { |info| close_owned(info[:pidfd_descriptor]) }
        end
        raise
      end

      def close_owned(resource)
        resource&.close unless resource&.closed?
      rescue Exception
        nil
      end
    end

    def initialize(attributes, notifier: nil, own_fds: false)
      @raw_mask = attributes.fetch(:raw_mask)
      @pid = attributes[:pid].negative? ? nil : attributes[:pid]
      @notifier = notifier
      @event_fd = attributes[:fd] unless attributes[:fd] == FAN_NOFD
      @response_mutex = Mutex.new
      @file_descriptor = attributes[:file_descriptor] if own_fds
      attributes.fetch(:infos).each { |info| apply_info(info, own_fds:) }
    end

    def mask
      EVENT_MASKS.filter_map { |name, value| name if (raw_mask & value).positive? }
    end

    def file
      @response_mutex.synchronize do
        raise Error, "event is closed" if closed?

        @file ||= @file_descriptor&.to_io&.dup
      end
    end

    def path
      @response_mutex.synchronize do
        raise Error, "event is closed" if closed?
        return unless @event_fd

        File.readlink("/proc/self/fd/#{@event_fd}")
      end
    rescue SystemCallError
      nil
    end

    def process_path
      return unless pid

      File.readlink("/proc/#{pid}/exe")
    rescue SystemCallError
      nil
    end

    def deleted? = path&.end_with?(" (deleted)") || false
    def overflow? = (raw_mask & FAN_Q_OVERFLOW).positive?
    def permission? = (raw_mask & Notifier::PERMISSION_MASK).positive?
    def responded? = @responded || false
    def deferred? = @deferred || false
    def closed? = @closed || false

    def allow!(audit: false) = respond!(FAN_ALLOW, audit:)
    def deny!(audit: false) = respond!(FAN_DENY, audit:)

    def defer!
      raise Error, "only permission events can be deferred" unless permission?
      raise Error, "event is not associated with a notifier" unless notifier

      @response_mutex.synchronize do
        raise Error, "event is closed" if closed?
        raise Error, "event has already been responded to" if responded?
        return self if deferred?

        Thread.handle_interrupt(Exception => :never) do
          notifier.__send__(:register_pending, self, @event_fd,
                            [@file_descriptor, @pidfd_descriptor].compact)
          @deferred = true
        end
      end
      self
    end

    def close
      @response_mutex.synchronize do
        return if closed?

        begin
          respond_without_lock(FAN_ALLOW, audit: false) if permission? && !responded? && notifier
        ensure
          active_error = $!
          close_error = nil
          if deferred?
            begin
              notifier.__send__(:unregister_pending, self)
            rescue StandardError => error
              close_error ||= error
            ensure
              @deferred = false
            end
          end
          [@file, @file_descriptor, @pidfd_descriptor].each do |resource|
            resource&.close unless resource&.closed?
          rescue StandardError => error
            close_error ||= error
          end
          @closed = true
          raise close_error if !active_error && close_error
        end
        nil
      end
    end

    private

    def respond!(response, audit:)
      raise Error, "not a permission event" unless permission?
      raise Error, "event is not associated with a notifier" unless notifier
      raise ArgumentError, "audit must be true or false" unless audit == true || audit == false

      @response_mutex.synchronize do
        raise Error, "event is closed" if closed?
        raise Error, "event has already been responded to" if responded?

        respond_without_lock(response, audit:)
      end
      self
    end

    def respond_without_lock(response, audit:)
      Thread.handle_interrupt(Exception => :never) do
        notifier.__send__(:respond_to_event, @event_fd, response | (audit ? FAN_AUDIT : 0))
        @responded = true
        notifier.__send__(:unregister_pending, self)
        @deferred = false
      end
    end

    def apply_info(info, own_fds:)
      case info.fetch(:type)
      when INFO_FID then @fid = file_handle(info)
      when INFO_DFID then @dfid = file_handle(info)
      when INFO_DFID_NAME then @dfid, @name = file_handle(info), info[:name]
      when INFO_OLD_DFID_NAME then @old_dfid, @old_name = file_handle(info), info[:name]
      when INFO_NEW_DFID_NAME then @new_dfid, @new_name = file_handle(info), info[:name]
      when INFO_PIDFD
        if info[:pidfd].negative?
          @pidfd_error = info[:pidfd]
        else
          @pidfd = info[:pidfd]
          @pidfd_descriptor = info[:pidfd_descriptor] if own_fds
        end
      when INFO_ERROR then @error, @error_count = info.values_at(:error, :error_count)
      when INFO_RANGE then @range_offset, @range_count = info.values_at(:range_offset, :range_count)
      end
    end

    def file_handle(info)
      FileHandle.new(fsid: info.fetch(:fsid), type: info.fetch(:handle_type), bytes: info.fetch(:handle))
    end
  end
end
