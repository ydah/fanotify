# frozen_string_literal: true

module Fanotify
  # One parsed fanotify event and any descriptors owned by it.
  class Event
    INFO_FID = 1
    INFO_DFID_NAME = 2
    INFO_DFID = 3
    INFO_PIDFD = 4
    INFO_ERROR = 5
    INFO_OLD_DFID_NAME = 10
    INFO_NEW_DFID_NAME = 12

    attr_reader :raw_mask, :pid, :notifier, :fid, :dfid, :name, :pidfd,
                :old_dfid, :old_name, :new_dfid, :new_name, :error, :error_count

    class << self
      def parse(buffer, notifier: nil, own_fds: false)
        Native.parse(buffer).map { |attributes| new(attributes, notifier:, own_fds:) }
      end
    end

    def initialize(attributes, notifier: nil, own_fds: false)
      @raw_mask = attributes.fetch(:raw_mask)
      @pid = attributes[:pid].negative? ? nil : attributes[:pid]
      @notifier = notifier
      @event_fd = attributes[:fd] unless attributes[:fd] == FAN_NOFD
      @response_mutex = Mutex.new
      @file_descriptor = Native.wrap(@event_fd) if own_fds && @event_fd
      attributes.fetch(:infos).each { |info| apply_info(info, own_fds:) }
    end

    def mask
      EVENT_MASKS.filter_map { |name, value| name if (raw_mask & value).positive? }
    end

    def file
      raise Error, "event is closed" if closed?

      @file_descriptor&.to_io
    end

    def path
      raise Error, "event is closed" if closed?
      return unless @event_fd

      File.readlink("/proc/self/fd/#{@event_fd}")
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
      raise Error, "event has already been responded to" if responded?
      raise Error, "event is not associated with a notifier" unless notifier

      return self if deferred?

      @deferred = true
      notifier.__send__(:register_pending, self, @event_fd)
      self
    end

    def close
      return if closed?

      begin
        allow! if permission? && !responded? && notifier
      ensure
        @file_descriptor&.close unless @file_descriptor&.closed?
        @pidfd_descriptor&.close unless @pidfd_descriptor&.closed?
        @closed = true
      end
      nil
    end

    private

    def respond!(response, audit:)
      raise Error, "not a permission event" unless permission?
      raise Error, "event is not associated with a notifier" unless notifier

      @response_mutex.synchronize do
        raise Error, "event has already been responded to" if responded?

        notifier.__send__(:respond_to_event, self, @event_fd, response | (audit ? FAN_AUDIT : 0))
        @responded = true
        @deferred = false
      end
      self
    end

    def apply_info(info, own_fds:)
      case info.fetch(:type)
      when INFO_FID then @fid = file_handle(info)
      when INFO_DFID then @dfid = file_handle(info)
      when INFO_DFID_NAME then @dfid, @name = file_handle(info), info[:name]
      when INFO_OLD_DFID_NAME then @old_dfid, @old_name = file_handle(info), info[:name]
      when INFO_NEW_DFID_NAME then @new_dfid, @new_name = file_handle(info), info[:name]
      when INFO_PIDFD
        @pidfd = info[:pidfd] unless info[:pidfd] == FAN_NOFD
        @pidfd_descriptor = Native.wrap(@pidfd) if own_fds && @pidfd
      when INFO_ERROR then @error, @error_count = info.values_at(:error, :error_count)
      end
    end

    def file_handle(info)
      FileHandle.new(fsid: info.fetch(:fsid), type: info.fetch(:handle_type), bytes: info.fetch(:handle))
    end
  end
end
