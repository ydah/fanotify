# frozen_string_literal: true

module Fanotify
  Mark = Data.define(:action, :path, :events, :on, :follow, :only_dir)
end
