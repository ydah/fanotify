# frozen_string_literal: true

require_relative "fanotify/version"
require "weakref"

module Fanotify
  class Error < StandardError; end
  class UnsupportedError < Error; end
  class PermissionError < Error; end
end

require "fanotify/fanotify"

module Fanotify
  Native.constants(false).grep(/^FAN|^O_|^AT_/).each { |name| const_set(name, Native.const_get(name)) }
end

require_relative "fanotify/file_handle"
require_relative "fanotify/event"
require_relative "fanotify/mark"
require_relative "fanotify/notifier"

module Fanotify
  class << self
    def supported? = Native.supported?

    def watch(path, events: %i[create delete modify], **options, &block)
      return enum_for(__method__, path, events:, **options) unless block

      options = {class: :notif, report: %i[fid dfid_name]}.merge(options)
      Notifier.open(**options) do |notifier|
        notifier.mark(:add, path, events: events + [:event_on_child], only_dir: true)
        notifier.each_event(&block)
      end
    end
  end
end
