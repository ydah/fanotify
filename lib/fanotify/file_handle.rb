# frozen_string_literal: true

module Fanotify
  # Opaque filesystem identifier reported by the kernel.
  FileHandle = Data.define(:fsid, :type, :bytes) do
    def initialize(fsid:, type:, bytes:)
      super(fsid: fsid.b.freeze, type:, bytes: bytes.b.freeze)
    end

    def to_s = bytes.unpack1("H*")
  end
end
