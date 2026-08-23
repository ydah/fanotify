# frozen_string_literal: true

module Fanotify
  # Immutable description of a fanotify mark operation.
  Mark = Data.define(:action, :path, :events, :on, :follow, :only_dir)
end
