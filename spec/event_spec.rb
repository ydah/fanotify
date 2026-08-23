# frozen_string_literal: true

RSpec.describe Fanotify::Event do
  def metadata(mask:, fd: -1, pid: 42, infos: "", version: Fanotify::FANOTIFY_METADATA_VERSION,
               event_len: nil, metadata_len: 24)
    event_len ||= metadata_len + infos.bytesize
    [event_len, version, 0, metadata_len, mask, fd, pid].pack("LCCSQll") + infos
  end

  def fid_info(type:, fsid: "12345678", handle_type: 7, handle: "\xaa\xbb".b, name: nil)
    body = fsid + [handle.bytesize, handle_type].pack("Ll") + handle + (name ? "#{name}\0" : "")
    [type, 0, 4 + body.bytesize].pack("CCS") + body
  end

  it "parses concatenated events and converts masks" do
    events = described_class.parse(
      metadata(mask: Fanotify::FAN_OPEN, pid: 1) +
      metadata(mask: Fanotify::FAN_MODIFY | Fanotify::FAN_ONDIR, pid: 2)
    )

    expect(events.map(&:pid)).to eq([1, 2])
    expect(events.last.mask).to contain_exactly(:modify, :ondir)
  end

  it "parses DFID names without treating handles as paths" do
    info = fid_info(type: described_class::INFO_DFID_NAME, name: "file.txt")
    event = described_class.parse(metadata(mask: Fanotify::FAN_CREATE, infos: info)).first

    expect(event.name).to eq("file.txt")
    expect(event.dfid).to have_attributes(fsid: "12345678", type: 7, bytes: "\xaa\xbb".b)
    expect(event.dfid.to_s).to eq("aabb")
  end

  it "parses PIDFD and filesystem error info" do
    pidfd = [described_class::INFO_PIDFD, 0, 8, 9].pack("CCSl")
    error = [described_class::INFO_ERROR, 0, 12, -5, 3].pack("CCSlL")
    event = described_class.parse(metadata(mask: Fanotify::FAN_FS_ERROR, infos: pidfd + error)).first

    expect(event).to have_attributes(pidfd: 9, error: -5, error_count: 3)
  end

  it "keeps both names from rename records" do
    old_info = fid_info(type: described_class::INFO_OLD_DFID_NAME, name: "old.txt")
    new_info = fid_info(type: described_class::INFO_NEW_DFID_NAME, name: "new.txt")
    event = described_class.parse(metadata(mask: Fanotify::FAN_RENAME, infos: old_info + new_info)).first

    expect(event).to have_attributes(old_name: "old.txt", new_name: "new.txt")
    expect(event.old_dfid).to eq(event.new_dfid)
  end

  it "rejects malformed kernel records" do
    expect { described_class.parse("short") }.to raise_error(ArgumentError, /truncated fanotify metadata/)
    expect { described_class.parse(metadata(mask: 0, version: 99)) }.to raise_error(ArgumentError, /version/)
    expect { described_class.parse(metadata(mask: 0, event_len: 0)) }.to raise_error(ArgumentError, /event length/)
    expect { described_class.parse(metadata(mask: 0, event_len: 48)) }.to raise_error(ArgumentError, /truncated fanotify event/)
  end

  it "rejects malformed info records" do
    bad_info = [described_class::INFO_FID, 0, 4].pack("CCS")
    expect { described_class.parse(metadata(mask: 0, infos: bad_info)) }
      .to raise_error(ArgumentError, /truncated FID/)
  end
end
